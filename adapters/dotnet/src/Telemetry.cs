// SPDX-License-Identifier: MIT
using System;
using Microsoft.Extensions.Logging;
using Opc.Ua;

namespace OpcUaInterop
{
    /// <summary>Stack logging to stderr (stdout is reserved for the one JSON result).</summary>
    internal static class Telemetry
    {
        public static ITelemetryContext Create(string component)
        {
            LogLevel level = ParseLevel(Environment.GetEnvironmentVariable("OPCUA_INTEROP_LOG_LEVEL"), LogLevel.Warning);
            return DefaultTelemetry.Create(b =>
            {
                b.ClearProviders();
                b.SetMinimumLevel(level);
                b.AddProvider(new StderrLoggerProvider(component, level));
            });
        }

        private static LogLevel ParseLevel(string s, LogLevel def) =>
            Enum.TryParse(s, true, out LogLevel l) ? l : def;
    }

    internal sealed class StderrLoggerProvider : ILoggerProvider
    {
        private readonly string m_component;
        private readonly LogLevel m_level;

        public StderrLoggerProvider(string component, LogLevel level)
        {
            m_component = component;
            m_level = level;
        }

        public ILogger CreateLogger(string categoryName) => new StderrLogger(m_component, categoryName, m_level);

        public void Dispose()
        {
        }

        private sealed class StderrLogger : ILogger
        {
            private readonly string m_component;
            private readonly string m_category;
            private readonly LogLevel m_level;

            public StderrLogger(string component, string category, LogLevel level)
            {
                m_component = component;
                int dot = category.LastIndexOf('.');
                m_category = dot >= 0 ? category[(dot + 1)..] : category;
                m_level = level;
            }

            public IDisposable BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => logLevel >= m_level && logLevel != LogLevel.None;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
            {
                if (!IsEnabled(logLevel))
                {
                    return;
                }
                string msg = formatter(state, exception);
                if (exception != null && logLevel >= LogLevel.Error)
                {
                    msg += " (" + exception.GetType().Name + ": " + exception.Message + ")";
                }
                Console.Error.WriteLine("[" + m_component + "] " + logLevel.ToString().ToLowerInvariant() + ": " + m_category + ": " + msg);
            }
        }
    }
}
