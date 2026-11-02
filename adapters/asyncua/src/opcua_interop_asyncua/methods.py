"""Fixture method behaviours (docs/FIXTURES.md "Methods").

asyncua's Call service hands the raw input Variants to the linked callback
and does no argument checking of its own; the callbacks therefore check the
argument count and types against the fixture definition, as an asyncua
application has to (Part 4 §5.11.2: BadArgumentsMissing, BadTooManyArguments,
BadInvalidArgument with per-argument BadTypeMismatch)."""

from __future__ import annotations

from asyncua import ua

_VT = {
    "Boolean": ua.VariantType.Boolean,
    "Int32": ua.VariantType.Int32,
    "Double": ua.VariantType.Double,
    "String": ua.VariantType.String,
}


def _check(inputs, defs) -> ua.CallMethodResult | None:
    if len(inputs) < len(defs):
        return ua.CallMethodResult(StatusCode=ua.StatusCode(ua.StatusCodes.BadArgumentsMissing))
    if len(inputs) > len(defs):
        return ua.CallMethodResult(StatusCode=ua.StatusCode(ua.StatusCodes.BadTooManyArguments))
    results = []
    bad = False
    for var, d in zip(inputs, defs):
        want = _VT.get(d.get("dataType"))
        if want is not None and (var is None or var.VariantType != want):
            results.append(ua.StatusCode(ua.StatusCodes.BadTypeMismatch))
            bad = True
        else:
            results.append(ua.StatusCode())
    if bad:
        return ua.CallMethodResult(StatusCode=ua.StatusCode(ua.StatusCodes.BadInvalidArgument), InputArgumentResults=results)
    return None


def make_method(behavior: str | None, nd: dict):
    in_defs = nd.get("inputArguments") or []

    async def method(parent, *inputs):
        err = _check(list(inputs), in_defs)
        if err is not None:
            return err
        vals = [v.Value for v in inputs]
        if behavior == "Add":
            s = (int(vals[0]) + int(vals[1]) + 2**31) % 2**32 - 2**31
            return [ua.Variant(s, ua.VariantType.Int32)]
        if behavior == "Multiply":
            return [ua.Variant(float(vals[0]) * float(vals[1]), ua.VariantType.Double)]
        if behavior == "Echo":
            return [ua.Variant(vals[0], ua.VariantType.String)]
        if behavior == "NoArguments":
            return [ua.Variant(True, ua.VariantType.Boolean)]
        if behavior == "MultipleOutputs":
            n = int(vals[0])
            doubled = (n * 2 + 2**31) % 2**32 - 2**31
            return [ua.Variant(doubled, ua.VariantType.Int32), ua.Variant(str(n), ua.VariantType.String)]
        if behavior == "Fail":
            return ua.StatusCode(ua.StatusCodes.BadInternalError)
        return ua.StatusCode(ua.StatusCodes.BadNotImplemented)

    return method
