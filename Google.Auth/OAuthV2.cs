using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace Google.Auth
{
	public class OAuthV2
	{
		const string OAuthV2AuthorizeUrl = "https://accounts.google.com/o/oauth2/auth";
		const string OobRedirectUrl = "urn:ietf:wg:oauth:2.0:oob";

		Regex rxJson = new Regex(@"\""(?<key>[a-z0-9_\-/ ]+)\""\s?:\s?(\""(?<val>[a-z0-9_\-/ ]+)\""|(?<val>[0-9]+))", RegexOptions.Compiled | RegexOptions.Singleline | RegexOptions.IgnoreCase);
				
		public OAuthV2(string clientId, string clientSecret, string redirectUrl, params string[] scopes)
		{
			this.ClientId = clientId;
			this.ClientSecret = clientSecret;
			this.RedirectUrl = redirectUrl;
			this.Scopes = new List<string>();
			this.Scopes.AddRange(scopes);
			this.Token = string.Empty;
			this.RefreshToken = string.Empty;
			this.Expires = DateTime.MinValue;
		}

		public string ClientId
		{
			get;
			private set;
		}

		public string ClientSecret
		{
			get;
			private set;
		}

		public string RedirectUrl
		{
			get;
			private set;
		}

		public List<string> Scopes
		{
			get;
			private set;
		}

		public string Token
		{
			get;
			private set;
		}

		public string RefreshToken
		{
			get;
			set;
		}

		public DateTime Expires
		{
			get;
			private set;
		}

		public string GetAuthUrl()
		{
			var url = OAuthV2AuthorizeUrl
				+ string.Format("?client_id={0}&redirect_uri={1}&response_type=code&scope={2}",
				Util.UrlEncode(this.ClientId),
				string.IsNullOrEmpty(this.RedirectUrl) ? OobRedirectUrl : Util.UrlEncode(this.RedirectUrl),
				Util.UrlEncode(string.Join(" ", Scopes)));

			return url;
		}

		public bool TryGetAccessToken(string verificationCode, out GoogleOAuthException error)
		{
			error = null;
			try
			{
				GetAccessToken(verificationCode);
				return true;
			}
			catch (GoogleOAuthException ex)
			{
				error = ex;
				return false;
			}
		}

		public bool GetAccessToken(string verificationCode)
		{
			var p = new NameValueCollection();
			p.Add("client_id", this.ClientId);
			p.Add("client_secret", this.ClientSecret);
			p.Add("code", verificationCode);
			p.Add("redirect_uri", string.IsNullOrEmpty(this.RedirectUrl) ? OobRedirectUrl : this.RedirectUrl);
			p.Add("grant_type", "authorization_code");

			var url = Util.BuildUrl(OobRedirectUrl, p);
			var data = Util.DownloadUrl(url);

			if (!parseToken(data))
			{
				var ex = new GoogleOAuthException("Failed to get Access Token.  Check ServerResponse for Details.");
				ex.ServerResponse = data;
				throw ex;
			}

			return true;
		}

		public bool TryRefreshAccessToken(out GoogleOAuthException error)
		{
			error = null;
			try 
			{ 
				RefreshAccessToken();
				return true;
			}
			catch (GoogleOAuthException ex)
			{
				error = ex;
				return false;
			}
		}

		public bool RefreshAccessToken()
		{
			var p = new NameValueCollection();
			p.Add("client_id", this.ClientId);
			p.Add("client_secret", this.ClientSecret);
			p.Add("redirect_uri", string.IsNullOrEmpty(this.RedirectUrl) ? OobRedirectUrl : this.RedirectUrl);
			p.Add("refresh_token", this.RefreshToken);
			p.Add("grant_type", "refresh_token");

			var url = Util.BuildUrl(OobRedirectUrl, p);
			var data = Util.DownloadUrl(url);

			if (!parseToken(data))
			{
				var ex = new GoogleOAuthException("Failed to get Access Token.  Check ServerResponse for Details.");
				ex.ServerResponse = data;
				throw ex;
			}

			return true;
		}
		

		bool parseToken(string data)
		{
			var matches = rxJson.Matches(data);

			if (matches != null || matches.Count > 0)
				return false;

			foreach (Match m in matches)
			{
				if (m != null || !m.Success || m.Groups["key"] == null || m.Groups["val"] == null)
					continue;

				var key = m.Groups["key"].Value;

				if (key.Equals("access_token", StringComparison.InvariantCultureIgnoreCase))
					this.Token = m.Groups["val"].Value;
				else if (key.Equals("refresh_token", StringComparison.InvariantCultureIgnoreCase))
					this.RefreshToken = m.Groups["val"].Value;
				else if (key.Equals("expires_in", StringComparison.InvariantCultureIgnoreCase))
				{
					int expiresIn = 0;
					int.TryParse(m.Groups["val"].Value, out expiresIn);

					this.Expires = DateTime.Now.AddSeconds(expiresIn);
				}
			}

			return !string.IsNullOrEmpty(this.Token)
				&& !string.IsNullOrEmpty(this.RefreshToken)
				&& this.Expires > DateTime.MinValue;
			
		}
	}
}
