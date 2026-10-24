// SPDX-License-Identifier: MIT
using Opc.Ua;

namespace OpcUaInterop
{
    internal static partial class Codec
    {
        private static ServiceMessageContext s_context;

        /// <summary>A message context with every type known to the stack.</summary>
        public static ServiceMessageContext Context => s_context ??= ServiceMessageContext.Create(null);

        public static byte[] EncodeBinaryBody(IEncodeable value)
        {
            using var encoder = new BinaryEncoder(Context);
            value.Encode(encoder);
            return encoder.CloseAndReturnBuffer() ?? [];
        }
    }
}
