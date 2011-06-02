using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace Google.Auth.Examples.OAuth3Legged
{
	public partial class frmBrowser : Form
	{
		public frmBrowser()
		{
			InitializeComponent();
		}

		Google.Auth.OAuth3Legged goauth;

		//Regex to parse the verifier code from google's "oob" callback page
		Regex rxVerifier = new Regex(@"\[ov:(?<ov>[^\[]+)\]", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline);

		private void frmBrowser_Load(object sender, EventArgs e)
		{
			//Handle the browser document completed even to check for the verifier code
			this.webBrowser.DocumentCompleted += new WebBrowserDocumentCompletedEventHandler(webBrowser_DocumentCompleted);

			goauth = new Auth.OAuth3Legged("test-app", //App name google logs
				"Test Application", //App name the user sees
				false, //Not mobile
				null, //oauth consumer key		null == "anonymous" <- for unregistered apps
				null, //oauth consumer secret	null == "anonymous" <- for unregistered apps
				null, //callback url			null == "oob"  <- google's own page for callback
				"https://mail.google.com/", // Scopes, this one is for Gmail
				"https://www.googleapis.com/auth/userinfo#email"
			);
						
			GoogleOAuthException err = null;
			string authUrl = string.Empty;

			//Start the process
			if (goauth.TryGetAuthUrl(out authUrl, out err))
				this.webBrowser.Navigate(authUrl);
			else
				MessageBox.Show(this, "OAuth Failed: " + err.ServerResponse, "Failed", MessageBoxButtons.OK);	
		}

		void webBrowser_DocumentCompleted(object sender, WebBrowserDocumentCompletedEventArgs e)
		{
			if (webBrowser.Document != null
				&& webBrowser.Document.Title != null
				&& rxVerifier.IsMatch(webBrowser.Document.Title))
			{
				//Match a pattern in google's 'oob' callback url
				// If you specified a different callback url than null or 'oob'
				// this won't work for you probably.
				var match = rxVerifier.Match(webBrowser.Document.Title);

				if (match != null && match.Groups["ov"] != null)
				{
					GoogleOAuthException err = null;

					//NEXT Step: Get Access Token with the verifier
					if (goauth.TryGetAccessToken(match.Groups["ov"].Value, out err))
					{
						var data = goauth.DownloadStringAuthenticated("https://www.googleapis.com/userinfo/email");
						var email = "Unknown Email!";

						if (data.StartsWith("email=", StringComparison.InvariantCultureIgnoreCase) && data.Contains('&'))
							email = data.Substring(6, data.IndexOf('&') - 6);

						MessageBox.Show(this, "Email of Authenticated User: " + email, "Success!", MessageBoxButtons.OK);
					}
					else
						MessageBox.Show(this, "OAuth Failed: " + err.ServerResponse, "Failed", MessageBoxButtons.OK);	
				}
			}
		}

		void goauth_OnUserAuthorizationPrompt(string url)
		{
			this.webBrowser.Navigate(url);
		}
	}
}
