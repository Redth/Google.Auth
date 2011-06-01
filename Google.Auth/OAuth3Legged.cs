/*
 *	Google OAuth 3-Legged for C#
 *	
 *	Author:		Redth
 *	Date:		June 1, 2011
 * 
 *	This class if for Authenticating to Google via 3-Legged OAuth
 *	
 *	Example Use:
 *	
 *			var goauth = new GoogleOAuthStep("my-app", "My Application",
 *				true, null, null, null, "emailofuserauthenticating@gmail.com",
 *				"https://www.google.com/m8/feeds/"); //Scope used here is google contacts
 *			
 *			goauth.OnUserAuthorizationPrompt += delegate(string url) {
 *				// Launch the url with the default system browser
 *				System.Diagnostics.Process.Start(url);
 *			
 *				Console.WriteLine("In the browser that opened, Grant Access to the Application");
 *				Console.WriteLine("Next, type in the Verification Code...:");
 *			
 *				//Get the verification code from the user
 *				return Console.ReadLine();
 *			};
 *		
 *			goauth.Authorize();
 *		
 *			Console.WriteLine("Access Token: " + goauth.Token);
 *			Console.WriteLine("Access Token Secret: " + goauth.TokenSecret);
 *		
 *			var valid = goauth.ValidateTokens(goauth.Token, goauth.TokenSecret);
 *		
 *			Console.WriteLine("Tokens Valid? " + valid.ToString());
 * 
 * 
 * 
 *	Notes:
 *		1. Obviously you will want to get a bit more fancy on how you handle the 
 *		   OnUserAuthorizationPrompt event. 
 *		2. If you specify a Callback Url to a page on your server it's easy enough
 *		   to parse out the request variables that google will send along to extract
 *		   the tokens.  Then you can have your client automatically detect the presence
 *		   of those tokens instead of making the user type them in like in the example.
 *		3. If you register your application with Google, you will need to supply a different
 *		   Consumer Key and Consumer Secret that Google gives you.  In the Example, we use
 *		   null which gets replaced with "anonymous" as per Google's documentation.
 *		4. We also use null for Callback Url which gets replaced with 'oob' as per google's
 *		   documentation.  This basically means google shows you the verification code on their
 *		   own page.
 * 
 */
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.Net;

namespace Google.Auth
{
	public enum GoogleOAuth3LeggedStep
	{
		GetRequestToken,
		AuthorizeToken,
		GetAccessToken,
		ValidateTokens
	}

	public class OAuth3Legged
	{
		public delegate void UserAuthorizationPromptDelegate(string url);
		public event UserAuthorizationPromptDelegate OnUserAuthorizationPrompt;

		const string OAuthGetRequestTokenUrl = "https://www.google.com/accounts/OAuthGetRequestToken";
		const string OAuthAuthorizeTokenUrl = "https://www.google.com/accounts/OAuthAuthorizeToken";
		const string OAuthGetAccessTokenUrl = "https://www.google.com/accounts/OAuthGetAccessToken";
		const string OAuthVerifyTokensUrl = "https://www.google.com/accounts/AuthSubTokenInfo";

		public OAuth3Legged(string appName,
			string displayName,
			bool mobile,
			string oauthConsumerKey,
			string oauthConsumerSecret,
			string oauthCallbackUrl,
			params string[] scopes)
		{
			this.Step = GoogleOAuth3LeggedStep.GetRequestToken;
			this.LastError = string.Empty;

			this.Scopes = scopes;
			this.DisplayName = displayName;
			this.Mobile = mobile;
			this.ConsumerKey = string.IsNullOrEmpty(oauthConsumerKey) ? "anonymous" : oauthConsumerKey;
			this.ConsumerSecret = string.IsNullOrEmpty(oauthConsumerSecret) ? "anonymous" : oauthConsumerSecret;
			this.CallbackUrl = string.IsNullOrEmpty(oauthCallbackUrl) ? "oob" : oauthCallbackUrl;
		}

		public GoogleOAuth3LeggedStep Step
		{
			get;
			private set;
		}

		public string LastError
		{
			get;
			private set;
		}

		public string ApplicationName
		{
			get;
			private set;
		}

		public string DisplayName
		{
			get;
			private set;
		}

		public bool Mobile
		{
			get;
			private set;
		}

		public string CallbackUrl
		{
			get;
			private set;
		}

		public string ConsumerKey
		{
			get;
			private set;
		}

		public string ConsumerSecret
		{
			get;
			private set;
		}

		public string Token
		{
			get;
			private set;
		}

		public string TokenSecret
		{
			get;
			private set;
		}

		public string[] Scopes
		{
			get;
			private set;
		}

		/// <summary>
		/// Validates the given token and tokenSecret to ensure it is still valid for the given scopes
		/// </summary>
		/// <param name="token">Access Token returned from Authorization</param>
		/// <param name="tokenSecret">Access Token Secret returned from Authorization</param>
		/// <returns>True if the Token is still valid and is valid for the given scopes</returns>
		public bool ValidateTokens(string token, string tokenSecret)
		{
			//This is largely unadvertised as a means to validate OAuth Token and token scope.
			// This is the documented way to get AuthSub info, but it works for OAuth too!
			this.Step = GoogleOAuth3LeggedStep.ValidateTokens;

			//Important that these parameters are in alpha order
			var p = new NameValueCollection();
			p.Add("oauth_consumer_key", this.ConsumerKey);
			p.Add("oauth_nonce", RandomInt64().ToString());
			p.Add("oauth_signature_method", "HMAC-SHA1");
			p.Add("oauth_timestamp", EpochNow().ToString());
			p.Add("oauth_token", token);
			p.Add("oauth_version", "1.0");

			//Build the signature
			p.Add("oauth_signature", GenerateSignature(OAuthVerifyTokensUrl, p, this.ConsumerSecret, tokenSecret));

			//Get a response
			var url = BuildUrl(OAuthVerifyTokensUrl, p);
			var data = DownloadUrl(url);

			//The respone from google comes in lines
			var lines = data.Split('\n');

			//No lines parsed? had an issue
			if (lines == null || lines.Length <= 0)
			{
				this.LastError = data;
				return false;
			}

			//We want to find all the valid scopes returned 
			// eg format:  Scope=...\nScope2=... etc.
			var validScopes = new List<string>();
			//There will be a line Secure=true if the token is valid still
			bool secure = false;

			//Parse out the lines
			foreach (var line in lines)
			{
				if (line.StartsWith("Scope", StringComparison.InvariantCultureIgnoreCase)
					&& line.Contains('='))
				{
					var scope = line.Substring(line.IndexOf('=') + 1);

					if (!string.IsNullOrEmpty(scope))
						validScopes.Add(scope);
				}
				else if (line.StartsWith("Secure=true", StringComparison.InvariantCultureIgnoreCase))
					secure = true;
			}

			//Find if any required scopes are missing from the valid scopes
			var missingScopes = from s in this.Scopes
								where !validScopes.Exists(vs => vs.Equals(s, StringComparison.InvariantCultureIgnoreCase))
								select s;

			if (missingScopes.Count() > 0)
			{
				this.LastError = "Missing Scopes:" + Environment.NewLine + string.Join(Environment.NewLine, missingScopes);
				return false;
			}

			if (!secure)
			{
				this.LastError = "Not Secured: " + data;
				return false;
			}

			return true;
		}

		/// <summary>
		/// Authorizes an account with OAuth for the specified Google scopes
		/// </summary>
		/// <returns>True if Authorization Succeeded, with the Token and TokenSecret properties populated</returns>
		public bool Auth()
		{
			//Step 1: Get Request Token
			// IMPORTANT NOTE: For the GenerateSignature to work properly all the parameters in this
			//  collection must be in alpha order!!!
			var p = new NameValueCollection();
			p.Add("oauth_callback", this.CallbackUrl);
			p.Add("oauth_consumer_key", this.ConsumerKey);
			p.Add("oauth_nonce", RandomInt64().ToString());
			p.Add("oauth_signature_method", "HMAC-SHA1");
			p.Add("oauth_timestamp", EpochNow().ToString());
			p.Add("oauth_version", "1.0");
			p.Add("scope", string.Join(" ", Scopes));
			p.Add("xoauth_displayname", DisplayName);

			//Add the last paramaeter which uses the existing ones to generate a signature
			p.Add("oauth_signature", GenerateSignature(OAuthGetRequestTokenUrl, p, this.ConsumerSecret, null));

			//Build the url and download the data
			var url = BuildUrl(OAuthGetRequestTokenUrl, p);
			var data = DownloadUrl(url);
			var responseParameters = ParseQueryString(data);

			//Parse out the tokens in the response
			this.Token = responseParameters["oauth_token"] ?? "";
			this.TokenSecret = responseParameters["oauth_token_secret"] ?? "";

			//If the tokens aren't there, we had an issue
			if (string.IsNullOrEmpty(this.Token)
				|| string.IsNullOrEmpty(this.TokenSecret))
			{
				this.LastError = data;
				return false;
			}

			//Step 2: Authorize the Token
			this.Step = GoogleOAuth3LeggedStep.AuthorizeToken;

			//Build the url to show the user
			url = string.Format("{0}?oauth_token={1}", OAuthAuthorizeTokenUrl, this.Token);

			//Mobile support can be forced
			if (Mobile)
				url += "&btmpl=mobile";

			if (this.OnUserAuthorizationPrompt != null)
				this.OnUserAuthorizationPrompt(url);

			return true;
		}

		public bool GetAccessToken(string verifier)
		{
			if (string.IsNullOrEmpty(verifier))
			{
				this.LastError = "Missing Verifier!";
				return false;
			}


			//Step 3: Get Access Token
			this.Step = GoogleOAuth3LeggedStep.GetAccessToken;

			//Again make sure these are in alpha order
			var p = new NameValueCollection();
			p.Add("oauth_consumer_key", this.ConsumerKey);
			p.Add("oauth_nonce", RandomInt64().ToString());
			p.Add("oauth_signature_method", "HMAC-SHA1");
			p.Add("oauth_timestamp", EpochNow().ToString());
			p.Add("oauth_token", this.Token);
			p.Add("oauth_verifier", verifier);
			p.Add("oauth_version", "1.0");

			//Generating the signature, this time we have a TokenSecret we must include
			p.Add("oauth_signature", GenerateSignature(OAuthGetAccessTokenUrl, p, this.ConsumerSecret, this.TokenSecret));

			//Get the response
			var url = BuildUrl(OAuthGetAccessTokenUrl, p);
			var data = DownloadUrl(url);
			var responseParameters = ParseQueryString(data);

			//Parse out the tokens in the response
			this.Token = responseParameters["oauth_token"] ?? "";
			this.TokenSecret = responseParameters["oauth_token_secret"] ?? "";

			//If we have no tokens, we had an issue
			if (string.IsNullOrEmpty(this.Token) || string.IsNullOrEmpty(this.TokenSecret))
			{
				this.LastError = data;
				return false;
			}

			//Everything went ok!
			return true;
		}

		string DownloadUrl(string url)
		{
			var wc = new WebClient();
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

		string BuildUrl(string baseUrl, NameValueCollection param)
		{
			var url = new StringBuilder();

			url.Append(baseUrl);
			url.Append("?");

			foreach (var key in param.AllKeys)
				url.AppendFormat("{0}={1}&", key, UrlEncode(param[key]));

			if (url.Length > 1)
				url.Remove(url.Length - 1, 1);

			return url.ToString();
		}

		string GenerateSignature(string baseUrl, NameValueCollection param, string consumerSecret, string tokenSecret)
		{
			var pStr = new StringBuilder();

			foreach (var key in param.AllKeys)
				pStr.AppendFormat("{0}={1}&", key, UrlEncode(param[key]));

			if (pStr.Length > 1) //Remove trailing &
				pStr.Remove(pStr.Length - 1, 1);

			var baseStr = string.Format("GET&{0}&{1}",
				UrlEncode(baseUrl),
				UrlEncode(pStr.ToString()));

			HMACSHA1 sha1 = new HMACSHA1();
			sha1.Key = Encoding.ASCII.GetBytes(UrlEncode(consumerSecret) + "&" + (string.IsNullOrEmpty(tokenSecret) ? "" : UrlEncode(tokenSecret)));

			return Convert.ToBase64String(sha1.ComputeHash(System.Text.Encoding.ASCII.GetBytes(baseStr)));
		}

		public string UrlEncode(string Input)
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

		public string UrlDecode(string data)
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

		ulong RandomInt64()
		{
			var rnd = new Random();
			var buffer = new byte[sizeof(ulong)];
			rnd.NextBytes(buffer);
			return BitConverter.ToUInt64(buffer, 0);
		}

		ulong EpochNow()
		{
			var epoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

			return (ulong)(DateTime.UtcNow - epoch).TotalSeconds;
		}

		NameValueCollection ParseQueryString(string data)
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
