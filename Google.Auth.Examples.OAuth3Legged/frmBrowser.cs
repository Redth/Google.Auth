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

			//Watch for when we need to navigate the user to login and grant access
			goauth.OnUserAuthorizationPrompt += new Auth.OAuth3Legged.UserAuthorizationPromptDelegate(goauth_OnUserAuthorizationPrompt);

			//Start the process
			goauth.Auth();
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
					//NEXT Step: Get Access Token with the verifier
					if (goauth.GetAccessToken(match.Groups["ov"].Value))
						MessageBox.Show(this, "Token: " + goauth.Token + "\r\nToken Secret: " + goauth.TokenSecret, "Success!", MessageBoxButtons.OK);
					else
						MessageBox.Show(this, "OAuth Failed: " + goauth.LastError, "Failed", MessageBoxButtons.OK);
				}
			}
		}

		void goauth_OnUserAuthorizationPrompt(string url)
		{
			//Show the user the url so they can login and/or grant access
			this.webBrowser.Navigate(url);
		}
	}
}
