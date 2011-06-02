using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace Google.Auth
{
	class Util
	{
		public static string DownloadUrl(string url)
		{
			return DownloadUrl(url, null);
		}

		public static string DownloadUrl(string url, params string[] headers)
		{
			var wc = new WebClient();
			
			if (headers != null)
				foreach (var h in headers)
					wc.Headers.Add(h);

			var data = string.Empty;

			try { data = wc.DownloadString(url); }
			catch (WebException wex)
			{
				try
				{
					using (var sr = new System.IO.StreamReader(wex.Response.GetResponseStream()))
					{
						data = sr.ReadToEnd();
					}
				}
				catch { }
			}
			return data;
		}

		public static string BuildOAuthHeader(NameValueCollection p)
		{
			var header = new StringBuilder();
			header.Append("Authorization: OAuth ");

			foreach (var key in p.AllKeys)
				header.AppendFormat("{0}=\"{1}\", ",
					key, UrlEncode(p[key]));

			return header.ToString();
		}

		public static string BuildUrl(string baseUrl, NameValueCollection param)
		{
			var url = new StringBuilder();

			url.Append(baseUrl);
			url.Append("?");

			foreach (var key in param.AllKeys)
				url.AppendFormat("{0}={1}&", key, Util.UrlEncode(param[key]));

			if (url.Length > 1)
				url.Remove(url.Length - 1, 1);

			return url.ToString();
		}

		public static string UrlEncode(string Input)
		{
			StringBuilder Result = new StringBuilder();
			for (int x = 0; x < Input.Length; ++x)
			{
				if ("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~"
					.IndexOf(Input[x]) != -1)
					Result.Append(Input[x]);
				else
					Result.Append("%").Append(String.Format("{0:X2}", (int)Input[x]));
			}
			return Result.ToString();
		}

		public static string UrlDecode(string data)
		{
			var result = data;
			var rxUrl = new Regex("%[A-Z0-9]{2}", RegexOptions.IgnoreCase | RegexOptions.Singleline);

			var matches = rxUrl.Matches(data);

			foreach (Match m in matches)
			{
				var hex = m.Value.TrimStart('%');

				if (m.Success)
					result = result.Replace(m.Value, new string((char)int.Parse(hex, System.Globalization.NumberStyles.HexNumber), 1));
			}

			return result;
		}

		public static ulong RandomInt64()
		{
			var rnd = new Random();
			var buffer = new byte[sizeof(ulong)];
			rnd.NextBytes(buffer);
			return BitConverter.ToUInt64(buffer, 0);
		}

		public static ulong EpochNow()
		{
			var epoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

			return (ulong)(DateTime.UtcNow - epoch).TotalSeconds;
		}

		public static NameValueCollection ParseQueryString(string data)
		{
			var results = new NameValueCollection();

			if (data.Contains('?'))
				data = data.Substring(data.IndexOf('?') + 1);

			var fields = data.Split('&');

			if (fields == null)
				return results;

			foreach (var field in fields)
			{
				var parts = field.Split(new char[] { '=' }, 2);

				if (parts != null && parts.Length >= 1)
					results.Add(parts[0], parts.Length == 2 ? UrlDecode(parts[1]) : "");
			}

			return results;
		}
	}
}
