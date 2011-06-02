using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Google.Auth
{
	public class GoogleOAuthException : Exception
	{
		public GoogleOAuthException(string message)
			: base(message)
		{
			this.ServerResponseCode = System.Net.HttpStatusCode.Accepted;
			this.ServerResponse = string.Empty;
		}

		public System.Net.HttpStatusCode ServerResponseCode
		{
			get;
			set;
		}

		public string ServerResponse
		{
			get;
			set;
		}

	}
}
