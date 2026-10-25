// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Globalization;

namespace OpcUaInterop
{
    /// <summary>"--flag value" command-line access (the last occurrence wins for Get).</summary>
    internal sealed class Args
    {
        private readonly string[] m_args;

        public Args(string[] args)
        {
            m_args = args ?? [];
        }

        public string[] Raw => m_args;

        public bool Has(string flag) => Array.IndexOf(m_args, flag) >= 0;

        public string Get(string flag)
        {
            string v = null;
            for (int i = 0; i < m_args.Length - 1; i++)
            {
                if (m_args[i] == flag)
                {
                    v = m_args[i + 1];
                }
            }
            return v;
        }

        public List<string> All(string flag)
        {
            var r = new List<string>();
            for (int i = 0; i < m_args.Length - 1; i++)
            {
                if (m_args[i] == flag)
                {
                    r.Add(m_args[i + 1]);
                }
            }
            return r;
        }

        public int GetInt(string flag, int def)
        {
            string v = Get(flag);
            if (v == null)
            {
                return def;
            }
            if (!int.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out int r))
            {
                throw new InputException("invalid integer for " + flag + ": " + v);
            }
            return r;
        }

        public long GetLong(string flag, long def)
        {
            string v = Get(flag);
            if (v == null)
            {
                return def;
            }
            if (!long.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out long r))
            {
                throw new InputException("invalid integer for " + flag + ": " + v);
            }
            return r;
        }

        public double GetDouble(string flag, double def)
        {
            string v = Get(flag);
            if (v == null)
            {
                return def;
            }
            if (!double.TryParse(v, NumberStyles.Float, CultureInfo.InvariantCulture, out double r))
            {
                throw new InputException("invalid number for " + flag + ": " + v);
            }
            return r;
        }

        public bool GetBool(string flag, bool def)
        {
            string v = Get(flag);
            if (v == null)
            {
                return def;
            }
            return v.Equals("true", StringComparison.OrdinalIgnoreCase) || v == "1";
        }
    }
}
