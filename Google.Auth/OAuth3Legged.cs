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

		public string DownloadStringAuthenticated(string url)
		{
			var p = new NameValueCollection();

			p.Add("oauth_consumer_key", this.ConsumerKey);
			p.Add("oauth_nonce", Util.RandomInt64().ToString());
			p.Add("oauth_signature_method", "HMAC-SHA1");
			p.Add("oauth_timestamp", Util.EpochNow().ToString());
			p.Add("oauth_token", this.Token);
			p.Add("oauth_version", "1.0");

			//Build the signature
			p.Add("oauth_signature", Util.GenerateSignature(url, p, this.ConsumerSecret, this.TokenSecret));

			var header = Util.BuildOAuthHeader(p);
						
			var data = Util.DownloadUrl(url, header);

			return data;
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
			p.Add("oauth_nonce", Util.RandomInt64().ToString());
			p.Add("oauth_signature_method", "HMAC-SHA1");
			p.Add("oauth_timestamp", Util.EpochNow().ToString());
			p.Add("oauth_token", token);
			p.Add("oauth_version", "1.0");

			//Build the signature
			p.Add("oauth_signature", Util.GenerateSignature(OAuthVerifyTokensUrl, p, this.ConsumerSecret, tokenSecret));

			//Get a response
			var url = Util.BuildUrl(OAuthVerifyTokensUrl, p);
			var data = Util.DownloadUrl(url);

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
			p.Add("oauth_nonce", Util.RandomInt64().ToString());
			p.Add("oauth_signature_method", "HMAC-SHA1");
			p.Add("oauth_timestamp", Util.EpochNow().ToString());
			p.Add("oauth_version", "1.0");
			p.Add("scope", string.Join(" ", Scopes));
			p.Add("xoauth_displayname", DisplayName);

			//Add the last paramaeter which uses the existing ones to generate a signature
			p.Add("oauth_signature", Util.GenerateSignature(OAuthGetRequestTokenUrl, p, this.ConsumerSecret, null));

			//Build the url and download the data
			var url = Util.BuildUrl(OAuthGetRequestTokenUrl, p);
			var data = Util.DownloadUrl(url);
			var responseParameters = Util.ParseQueryString(data);

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
			p.Add("oauth_nonce", Util.RandomInt64().ToString());
			p.Add("oauth_signature_method", "HMAC-SHA1");
			p.Add("oauth_timestamp", Util.EpochNow().ToString());
			p.Add("oauth_token", this.Token);
			p.Add("oauth_verifier", verifier);
			p.Add("oauth_version", "1.0");

			//Generating the signature, this time we have a TokenSecret we must include
			p.Add("oauth_signature", Util.GenerateSignature(OAuthGetAccessTokenUrl, p, this.ConsumerSecret, this.TokenSecret));

			//Get the response
			var url = Util.BuildUrl(OAuthGetAccessTokenUrl, p);
			var data = Util.DownloadUrl(url);
			var responseParameters = Util.ParseQueryString(data);

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
	}
}
