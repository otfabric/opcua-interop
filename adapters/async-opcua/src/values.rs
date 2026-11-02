//! Value encoding to JSON (CONTAINER_CONTRACT §7) and value literals (§12).

use std::str::FromStr;

use opcua::types::{
    Array, ByteString, ContextOwned, DataValue, DateTime, DecodingOptions, DiagnosticInfo,
    ExtensionObject, Guid, LocalizedText, NamespaceMap, QualifiedName, StatusCode, UAString,
    Variant, VariantScalarTypeId, XmlElement,
};
use serde_json::{json, Map, Value};

use crate::common::status_json;
use crate::nodeid::{
    b64, b64_decode, fmt_expanded_node_id, fmt_node_id, parse_expanded_node_id,
    parse_node_id_literal,
};

pub const TYPE_NAMES: [&str; 26] = [
    "Null",
    "Boolean",
    "SByte",
    "Byte",
    "Int16",
    "UInt16",
    "Int32",
    "UInt32",
    "Int64",
    "UInt64",
    "Float",
    "Double",
    "String",
    "DateTime",
    "Guid",
    "ByteString",
    "XmlElement",
    "NodeId",
    "ExpandedNodeId",
    "StatusCode",
    "QualifiedName",
    "LocalizedText",
    "ExtensionObject",
    "DataValue",
    "Variant",
    "DiagnosticInfo",
];

pub fn type_name(id: u32) -> &'static str {
    TYPE_NAMES.get(id as usize).copied().unwrap_or("Null")
}

pub fn scalar_type_from_name(name: &str) -> Option<VariantScalarTypeId> {
    let idx = TYPE_NAMES.iter().position(|n| *n == name)?;
    if idx == 0 {
        return None;
    }
    VariantScalarTypeId::try_from(idx as u32).ok()
}

pub fn fmt_datetime(dt: &DateTime) -> String {
    dt.as_chrono().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

fn float_json(f: f64) -> Value {
    if f.is_finite() {
        serde_json::Number::from_f64(f)
            .map(Value::Number)
            .unwrap_or(Value::Null)
    } else {
        Value::Null
    }
}

fn f32_json(f: f32) -> Value {
    if f.is_finite() {
        // Shortest representation of the f32, not of its f64 widening.
        let s = format!("{f}");
        float_json(s.parse::<f64>().unwrap_or(f as f64))
    } else {
        Value::Null
    }
}

pub fn ua_str(s: &UAString) -> String {
    s.value().clone().unwrap_or_default()
}

pub fn localized_text_json(lt: &LocalizedText) -> Value {
    json!({"locale": ua_str(&lt.locale), "text": ua_str(&lt.text)})
}

pub fn qualified_name_json(q: &QualifiedName) -> Value {
    json!({"ns": q.namespace_index, "name": ua_str(&q.name)})
}

fn default_ctx() -> ContextOwned {
    ContextOwned::new_default(NamespaceMap::new(), DecodingOptions::default())
}

pub fn extension_object_json(eo: &ExtensionObject) -> Value {
    let Some(body) = &eo.body else {
        return Value::Null;
    };
    let ctx = default_ctx();
    let mut buf: Vec<u8> = Vec::new();
    let _ = body.encode_binary(&mut buf, &ctx.context());
    let mut m = Map::new();
    m.insert(
        "typeId".into(),
        json!(fmt_expanded_node_id(&body.binary_type_id())),
    );
    m.insert("encoding".into(), json!("binary"));
    m.insert("body".into(), json!(b64(&buf)));
    m.insert("dataTypeName".into(), json!(body.type_name()));
    Value::Object(m)
}

pub fn diagnostic_info_json(d: &DiagnosticInfo) -> Value {
    let mut m = Map::new();
    if let Some(v) = d.symbolic_id {
        m.insert("symbolicId".into(), json!(v));
    }
    if let Some(v) = d.namespace_uri {
        m.insert("namespaceUri".into(), json!(v));
    }
    if let Some(v) = d.localized_text {
        m.insert("localizedText".into(), json!(v));
    }
    if let Some(v) = d.locale {
        m.insert("locale".into(), json!(v));
    }
    if let Some(v) = &d.additional_info {
        m.insert("additionalInfo".into(), json!(ua_str(v)));
    }
    if let Some(v) = d.inner_status_code {
        m.insert("innerStatusCode".into(), status_json(v));
    }
    if let Some(v) = &d.inner_diagnostic_info {
        m.insert("innerDiagnosticInfo".into(), diagnostic_info_json(v));
    }
    Value::Object(m)
}

/// The canonical DataValue object of §7.
pub fn data_value_json(dv: &DataValue) -> Value {
    let mut m = Map::new();
    let (dt, bit, val, dims) = match &dv.value {
        Some(v) => {
            let (dt, bit, val) = variant_json(v);
            (dt, bit, val, matrix_dims(v))
        }
        None => ("Null".to_owned(), 0, Value::Null, None),
    };
    m.insert("dataType".into(), json!(dt));
    m.insert("builtInType".into(), json!(bit));
    if let Some(d) = dims {
        m.insert("arrayDimensions".into(), json!(d));
    }
    m.insert("value".into(), val);
    if let Some(s) = dv.status {
        m.insert("statusCode".into(), status_json(s));
    }
    if let Some(t) = &dv.source_timestamp {
        m.insert("sourceTimestamp".into(), json!(fmt_datetime(t)));
    }
    if let Some(p) = dv.source_picoseconds {
        m.insert("sourcePicoseconds".into(), json!(p));
    }
    if let Some(t) = &dv.server_timestamp {
        m.insert("serverTimestamp".into(), json!(fmt_datetime(t)));
    }
    if let Some(p) = dv.server_picoseconds {
        m.insert("serverPicoseconds".into(), json!(p));
    }
    Value::Object(m)
}

/// Dimensions of a matrix variant (rank > 1), else None.
pub fn matrix_dims(v: &Variant) -> Option<Vec<u32>> {
    if let Variant::Array(a) = v {
        if let Some(d) = &a.dimensions {
            if d.len() > 1 {
                return Some(d.clone());
            }
        }
    }
    None
}

/// ValueRank of a variant value: -1 scalar, 1 array, n matrix.
pub fn value_rank(v: &Variant) -> i32 {
    match v {
        Variant::Array(a) => match &a.dimensions {
            Some(d) if d.len() > 1 => d.len() as i32,
            _ => 1,
        },
        _ => -1,
    }
}

/// JSON of a scalar variant value (no type wrapper).
pub fn scalar_json(v: &Variant) -> Value {
    match v {
        Variant::Empty => Value::Null,
        Variant::Boolean(b) => json!(b),
        Variant::SByte(n) => json!(n),
        Variant::Byte(n) => json!(n),
        Variant::Int16(n) => json!(n),
        Variant::UInt16(n) => json!(n),
        Variant::Int32(n) => json!(n),
        Variant::UInt32(n) => json!(n),
        Variant::Int64(n) => json!(n.to_string()),
        Variant::UInt64(n) => json!(n.to_string()),
        Variant::Float(f) => f32_json(*f),
        Variant::Double(f) => float_json(*f),
        Variant::String(s) => match s.value() {
            Some(s) => json!(s),
            None => Value::Null,
        },
        Variant::DateTime(d) => json!(fmt_datetime(d)),
        Variant::Guid(g) => json!(g.to_string().to_lowercase()),
        Variant::StatusCode(s) => status_json(*s),
        Variant::ByteString(b) => match &b.value {
            Some(d) => json!(b64(d)),
            None => Value::Null,
        },
        Variant::XmlElement(x) => json!(x.to_string()),
        Variant::QualifiedName(q) => qualified_name_json(q),
        Variant::LocalizedText(l) => localized_text_json(l),
        Variant::NodeId(n) => json!(fmt_node_id(n)),
        Variant::ExpandedNodeId(n) => json!(fmt_expanded_node_id(n)),
        Variant::ExtensionObject(e) => extension_object_json(e),
        Variant::Variant(inner) => {
            let (dt, bit, val) = variant_json(inner);
            json!({"dataType": dt, "builtInType": bit, "value": val})
        }
        Variant::DataValue(dv) => data_value_json(dv),
        Variant::DiagnosticInfo(d) => diagnostic_info_json(d),
        Variant::Array(a) => Value::Array(a.values.iter().map(scalar_json).collect()),
    }
}

fn scalar_type_id(v: &Variant) -> u32 {
    match v {
        Variant::Empty => 0,
        Variant::Array(a) => a.value_type as u32,
        other => other.scalar_type_id().map(|t| t as u32).unwrap_or(0),
    }
}

/// (dataType name, builtInType, value) of a variant; arrays and matrices are
/// JSON arrays (matrices flattened row-major).
pub fn variant_json(v: &Variant) -> (String, u32, Value) {
    let id = scalar_type_id(v);
    (type_name(id).to_owned(), id, scalar_json(v))
}

// ── Literals ────────────────────────────────────────────────────────────────

fn parse_bool(s: &str) -> Result<bool, String> {
    match s.trim() {
        "true" | "True" | "TRUE" | "1" => Ok(true),
        "false" | "False" | "FALSE" | "0" => Ok(false),
        _ => Err(format!("invalid Boolean literal '{s}'")),
    }
}

fn parse_num<T: FromStr>(s: &str, ty: &str) -> Result<T, String> {
    s.trim()
        .parse::<T>()
        .map_err(|_| format!("invalid {ty} literal '{s}'"))
}

fn parse_float(s: &str) -> Result<f64, String> {
    match s.trim() {
        "NaN" => Ok(f64::NAN),
        "Infinity" | "+Infinity" | "INF" => Ok(f64::INFINITY),
        "-Infinity" | "-INF" => Ok(f64::NEG_INFINITY),
        t => t
            .parse::<f64>()
            .map_err(|_| format!("invalid floating point literal '{s}'")),
    }
}

pub fn parse_datetime(s: &str) -> Result<DateTime, String> {
    let dt = chrono::DateTime::parse_from_rfc3339(s.trim())
        .map_err(|e| format!("invalid DateTime literal '{s}': {e}"))?;
    Ok(DateTime::from(dt.with_timezone(&chrono::Utc)))
}

fn parse_status(s: &str) -> Result<StatusCode, String> {
    let t = s.trim();
    let v = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u32::from_str_radix(h, 16)
    } else {
        t.parse::<u32>()
    }
    .map_err(|_| format!("invalid StatusCode literal '{s}'"))?;
    Ok(StatusCode::from(v))
}

fn parse_diagnostic_info(s: &str) -> Result<DiagnosticInfo, String> {
    let mut d = DiagnosticInfo::default();
    for part in s.split(';').filter(|p| !p.is_empty()) {
        let (k, v) = part
            .split_once('=')
            .ok_or_else(|| format!("invalid DiagnosticInfo member '{part}'"))?;
        match k {
            "symbolicId" => d.symbolic_id = Some(parse_num(v, "Int32")?),
            "namespaceUri" => d.namespace_uri = Some(parse_num(v, "Int32")?),
            "localizedText" => d.localized_text = Some(parse_num(v, "Int32")?),
            "locale" => d.locale = Some(parse_num(v, "Int32")?),
            "additionalInfo" => d.additional_info = Some(UAString::from(v)),
            "innerStatusCode" => d.inner_status_code = Some(parse_status(v)?),
            _ => return Err(format!("unknown DiagnosticInfo member '{k}'")),
        }
    }
    Ok(d)
}

/// Parse one scalar literal of the given built-in type.
pub fn parse_scalar(ty: VariantScalarTypeId, s: &str) -> Result<Variant, String> {
    use VariantScalarTypeId as T;
    Ok(match ty {
        T::Boolean => Variant::Boolean(parse_bool(s)?),
        T::SByte => Variant::SByte(parse_num(s, "SByte")?),
        T::Byte => Variant::Byte(parse_num(s, "Byte")?),
        T::Int16 => Variant::Int16(parse_num(s, "Int16")?),
        T::UInt16 => Variant::UInt16(parse_num(s, "UInt16")?),
        T::Int32 => Variant::Int32(parse_num(s, "Int32")?),
        T::UInt32 => Variant::UInt32(parse_num(s, "UInt32")?),
        T::Int64 => Variant::Int64(parse_num(s, "Int64")?),
        T::UInt64 => Variant::UInt64(parse_num(s, "UInt64")?),
        T::Float => Variant::Float(parse_float(s)? as f32),
        T::Double => Variant::Double(parse_float(s)?),
        T::String => Variant::String(UAString::from(s)),
        T::DateTime => Variant::from(parse_datetime(s)?),
        T::Guid => Variant::from(
            Guid::from_str(s.trim()).map_err(|_| format!("invalid Guid literal '{s}'"))?,
        ),
        T::ByteString => Variant::ByteString(ByteString::from(b64_decode(s)?)),
        T::XmlElement => Variant::XmlElement(XmlElement::from(s)),
        T::NodeId => Variant::from(parse_node_id_literal(s)?),
        T::ExpandedNodeId => Variant::from(parse_expanded_node_id(s)?),
        T::StatusCode => Variant::StatusCode(parse_status(s)?),
        T::QualifiedName => {
            let (ns, name) = s
                .split_once(':')
                .ok_or_else(|| format!("invalid QualifiedName literal '{s}' (want <ns>:<name>)"))?;
            Variant::from(QualifiedName::new(parse_num::<u16>(ns, "namespace index")?, name))
        }
        T::LocalizedText => {
            let (loc, text) = s
                .split_once(':')
                .ok_or_else(|| format!("invalid LocalizedText literal '{s}' (want <locale>:<text>)"))?;
            Variant::from(LocalizedText::new(loc, text))
        }
        T::ExtensionObject => {
            return Err(
                "ExtensionObject literals are not supported by this adapter (async-opcua cannot \
                 build an ExtensionObject from an arbitrary binary body)"
                    .into(),
            )
        }
        T::DataValue => {
            let inner = parse_typed(s)?;
            Variant::from(DataValue::value_only(inner))
        }
        T::Variant => Variant::Variant(Box::new(parse_typed(s)?)),
        T::DiagnosticInfo => Variant::DiagnosticInfo(Box::new(parse_diagnostic_info(s)?)),
    })
}

/// `<Type>:<literal>` (used inside Variant / DataValue literals and `call --input`).
pub fn parse_typed(s: &str) -> Result<Variant, String> {
    let (ty, lit) = s
        .split_once(':')
        .ok_or_else(|| format!("invalid typed literal '{s}' (want <Type>:<literal>)"))?;
    parse_literal(ty, lit)
}

/// Split an array literal: JSON array or comma-separated; empty = no elements.
pub fn split_array_literal(s: &str) -> Result<Vec<String>, String> {
    let t = s.trim();
    if t.is_empty() {
        return Ok(Vec::new());
    }
    if t.starts_with('[') {
        let v: Vec<Value> =
            serde_json::from_str(t).map_err(|e| format!("invalid JSON array literal: {e}"))?;
        return Ok(v
            .into_iter()
            .map(|e| match e {
                Value::String(s) => s,
                other => other.to_string(),
            })
            .collect());
    }
    Ok(t.split(',').map(|p| p.to_owned()).collect())
}

/// Parse `--type` / `--value`: a scalar, or `<Type>[]` array.
pub fn parse_literal(type_name: &str, value: &str) -> Result<Variant, String> {
    if let Some(elem) = type_name.strip_suffix("[]") {
        let ty = scalar_type_from_name(elem)
            .ok_or_else(|| format!("unknown type '{type_name}'"))?;
        let parts = split_array_literal(value)?;
        let mut vals = Vec::with_capacity(parts.len());
        for p in parts {
            let v = parse_scalar(ty, &p)?;
            // Array elements of type Variant are stored as the nested variant.
            vals.push(v);
        }
        let arr = Array::new(ty, vals).map_err(|e| format!("invalid array: {e:?}"))?;
        return Ok(Variant::from(arr));
    }
    let ty =
        scalar_type_from_name(type_name).ok_or_else(|| format!("unknown type '{type_name}'"))?;
    if ty == VariantScalarTypeId::Variant {
        // As a scalar a Variant literal *is* its inner value.
        return parse_typed(value);
    }
    parse_scalar(ty, value)
}

/// Same as [parse_literal] but with the pre-v0.7.0 leniency of `write` /
/// `call`: an unknown type or malformed literal becomes a String variant.
pub fn parse_literal_lenient(type_name: &str, value: &str) -> Variant {
    match parse_literal(type_name, value) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("literal {type_name}:{value} not parsed ({e}); sending it as String");
            Variant::String(UAString::from(value))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lit(ty: &str, v: &str) -> Variant {
        parse_literal(ty, v).unwrap_or_else(|e| panic!("{ty}:{v}: {e}"))
    }

    #[test]
    fn type_names_follow_the_built_in_type_ids() {
        assert_eq!(TYPE_NAMES.len(), 26);
        assert_eq!(type_name(6), "Int32");
        assert_eq!(type_name(25), "DiagnosticInfo");
        assert_eq!(type_name(99), "Null");
        for (id, name) in TYPE_NAMES.iter().enumerate().skip(1) {
            assert_eq!(scalar_type_from_name(name).map(|t| t as u32), Some(id as u32), "{name}");
        }
        assert!(scalar_type_from_name("Null").is_none());
        assert!(scalar_type_from_name("Int33").is_none());
    }

    #[test]
    fn scalar_literals_encode_canonically() {
        let cases: &[(&str, &str, Value)] = &[
            ("Boolean", "true", json!(true)),
            ("SByte", "-128", json!(-128)),
            ("Byte", "255", json!(255)),
            ("Int16", "-32768", json!(-32768)),
            ("UInt16", "65535", json!(65535)),
            ("Int32", "-123456789", json!(-123456789)),
            ("UInt32", "4294967295", json!(4294967295u32)),
            // 64-bit integers are strings (§7), so no precision is lost.
            ("Int64", "-9223372036854775808", json!("-9223372036854775808")),
            ("UInt64", "18446744073709551615", json!("18446744073709551615")),
            ("Double", "3.14159", json!(3.14159)),
            ("String", "hello", json!("hello")),
            ("DateTime", "2026-01-02T03:04:05.678Z", json!("2026-01-02T03:04:05.678Z")),
            ("Guid", "72962B91-FA75-4AE6-8D28-B404DC7DAF63", json!("72962b91-fa75-4ae6-8d28-b404dc7daf63")),
            ("ByteString", "AQID", json!("AQID")),
            ("NodeId", "ns=1;s=x", json!("ns=1;s=x")),
            ("ExpandedNodeId", "nsu=urn:x;i=7", json!("nsu=urn:x;i=7")),
            ("QualifiedName", "1:Name", json!({"ns": 1, "name": "Name"})),
            ("LocalizedText", "en:Text", json!({"locale": "en", "text": "Text"})),
            ("StatusCode", "0x80340000", json!({"name": "BadNodeIdUnknown", "code": 0x8034_0000u32, "severity": "Bad"})),
        ];
        for (ty, v, want) in cases {
            let (dt, bit, got) = variant_json(&lit(ty, v));
            assert_eq!(&dt, ty);
            assert_eq!(bit as usize, TYPE_NAMES.iter().position(|n| n == ty).unwrap());
            assert_eq!(&got, want, "{ty}:{v}");
        }
    }

    #[test]
    fn float_uses_the_shortest_f32_representation() {
        assert_eq!(scalar_json(&lit("Float", "1.1")), json!(1.1));
        assert_eq!(scalar_json(&lit("Double", "NaN")), Value::Null);
        assert_eq!(scalar_json(&lit("Float", "-Infinity")), Value::Null);
    }

    #[test]
    fn arrays_and_matrices() {
        let a = lit("Int32[]", "[1,2,3]");
        assert_eq!(value_rank(&a), 1);
        assert_eq!(variant_json(&a), ("Int32".to_owned(), 6, json!([1, 2, 3])));
        assert_eq!(lit("String[]", "a,b"), lit("String[]", r#"["a","b"]"#));
        let empty = lit("Double[]", "");
        assert_eq!(variant_json(&empty).2, json!([]));
        assert_eq!(value_rank(&empty), 1);
        assert!(matrix_dims(&a).is_none());

        let m = Variant::from(
            Array::new_multi(
                VariantScalarTypeId::Int32,
                (1..=6).map(Variant::Int32).collect::<Vec<_>>(),
                vec![2, 3],
            )
            .unwrap(),
        );
        assert_eq!(value_rank(&m), 2);
        assert_eq!(matrix_dims(&m), Some(vec![2, 3]));
        let dv = data_value_json(&DataValue::value_only(m));
        assert_eq!(dv["arrayDimensions"], json!([2, 3]));
        assert_eq!(dv["value"], json!([1, 2, 3, 4, 5, 6]));
    }

    #[test]
    fn nested_variant_and_data_value_literals() {
        let v = lit("Variant", "Int32:5");
        assert_eq!(v, Variant::Int32(5), "a scalar Variant literal is its inner value");
        let arr = lit("Variant[]", r#"["Int32:1","String:x"]"#);
        assert_eq!(
            scalar_json(&arr),
            json!([
                {"dataType": "Int32", "builtInType": 6, "value": 1},
                {"dataType": "String", "builtInType": 12, "value": "x"}
            ])
        );
        let dv = lit("DataValue", "Double:2.5");
        assert_eq!(scalar_json(&dv)["value"], json!(2.5));
    }

    #[test]
    fn data_value_object() {
        let mut dv = DataValue::value_only(Variant::Int32(7));
        dv.status = Some(StatusCode::UncertainLastUsableValue);
        dv.source_timestamp = Some(parse_datetime("2026-07-24T10:00:00Z").unwrap());
        let j = data_value_json(&dv);
        assert_eq!(j["dataType"], json!("Int32"));
        assert_eq!(j["builtInType"], json!(6));
        assert_eq!(j["value"], json!(7));
        assert_eq!(j["statusCode"]["severity"], json!("Uncertain"));
        assert_eq!(j["sourceTimestamp"], json!("2026-07-24T10:00:00.000Z"));
        assert!(j.get("serverTimestamp").is_none());
        let empty = data_value_json(&DataValue::default());
        assert_eq!(empty["dataType"], json!("Null"));
        assert_eq!(empty["value"], Value::Null);
    }

    #[test]
    fn diagnostic_info_literal() {
        let v = lit("DiagnosticInfo", "symbolicId=1;additionalInfo=more;innerStatusCode=0x80000000");
        assert_eq!(
            scalar_json(&v),
            json!({"symbolicId": 1, "additionalInfo": "more", "innerStatusCode": {"name": "Bad", "code": 0x8000_0000u32, "severity": "Bad"}})
        );
    }

    #[test]
    fn rejects_malformed_literals() {
        for (ty, v) in [
            ("Boolean", "yes"),
            ("Byte", "256"),
            ("SByte", "-129"),
            ("Int32", "1.5"),
            ("UInt64", "-1"),
            ("DateTime", "yesterday"),
            ("Guid", "nope"),
            ("ByteString", "%%"),
            ("QualifiedName", "noseparator"),
            ("ExtensionObject", "AAAA"),
            ("Int33", "1"),
            ("Int32[]", "[1,\"x\"]"),
            ("DiagnosticInfo", "bogus=1"),
        ] {
            assert!(parse_literal(ty, v).is_err(), "{ty}:{v} must be rejected");
        }
    }

    #[test]
    fn lenient_literals_fall_back_to_string() {
        assert_eq!(parse_literal_lenient("Int32", "abc"), Variant::String(UAString::from("abc")));
        assert_eq!(parse_literal_lenient("Int32", "12"), Variant::Int32(12));
    }
}
