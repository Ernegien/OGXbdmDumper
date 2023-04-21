
namespace OGXbdmDumper
{
    /// <summary>
    /// Xbox command status response.
    /// </summary>
    public class CommandResponse
    {
        /// <summary>
        /// The full command response.
        /// </summary>
        public string Full { get; }

        /// <summary>
        /// The command response code.
        /// </summary>
        public int Code { get; }

        /// <summary>
        /// The message portion of the command response.
        /// </summary>
        public string Message { get; }

        /// <summary>
        /// TODO: description
        /// </summary>
        public bool Success => (Code & 200) == 200;

        /// <summary>
        /// TODO: description
        /// </summary>
        /// <param name="full"></param>
        /// <param name="code"></param>
        /// <param name="message"></param>
        public CommandResponse(string full, int code, string message)
        {
            Full = full;
            Code = code;
            Message = message;
        }
    }
}
