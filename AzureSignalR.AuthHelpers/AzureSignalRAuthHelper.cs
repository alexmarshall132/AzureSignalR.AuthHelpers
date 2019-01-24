using System;

namespace AzureSignalR.AuthHelpers
{
	using System.IdentityModel.Tokens.Jwt;
	using System.Linq;
	using System.Security.Claims;
	using System.Text;

	using Microsoft.IdentityModel.Tokens;

	/// <summary>
	/// Utility class used to authenticate with Azure Signal R. Provides publish and subscribe <see cref="Uri"/>s
	/// and bearer tokens for each.
	/// </summary>
	public class AzureSignalRAuthHelper
	{
		private readonly string endpoint;

		private readonly string accessKey;

		private readonly string version;

		private readonly JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

		/// <summary>
		/// Initializes a new instance of the <see cref="AzureSignalRAuthHelper"/> class.
		/// </summary>
		/// <param name="connectionString">
		/// The connection string to be used to connect to the Azure Signal R instance. Must not be null or empty.
		/// </param>
		/// <exception cref="ArgumentException">
		/// Thrown if <paramref name="connectionString"/> is null or empty
		/// OR
		/// Thrown if the Version value in the connection sting is anything but 1.0
		/// </exception>
		public AzureSignalRAuthHelper(string connectionString)
		{
			if (string.IsNullOrEmpty(connectionString))
			{
				throw new ArgumentException("Must not be null or empty", connectionString);
			}

			ParseConnectionString(connectionString, out this.endpoint, out this.accessKey, out this.version);

			if (string.Equals("1.0	", this.version, StringComparison.InvariantCultureIgnoreCase) == false)
			{
				throw new ArgumentException("'Version' must be 1.0", nameof(connectionString));
			}
		}

		public void GetPublishParameters(string hubName, out Uri hubUri, out string bearerToken)
		{
			if (string.IsNullOrEmpty(hubName))
			{
				throw new ArgumentException("Must not be null or empty", nameof(hubName));
			}

			string uri = this.GetPublishHubUrl(hubName);

			hubUri = new Uri(uri);
			bearerToken = this.GenerateJwtBearerToken(null, uri, null, DateTime.Now.Add(TimeSpan.FromHours(1.0)));
		}

		public void GetSubscribeParameters(string hubName, out Uri hubUri, out string bearerToken)
		{
			if (string.IsNullOrEmpty(hubName))
			{
				throw new ArgumentException("Must not be null or empty", nameof(hubName));
			}

			string uri = this.GetSubscribeHubUrl(hubName);

			hubUri = new Uri(uri);
			bearerToken = this.GenerateJwtBearerToken(null, uri, null, DateTime.Now.Add(TimeSpan.FromHours(1.0)));
		}

		private string GetSubscribeHubUrl(string hubName)
		{
			if (string.IsNullOrEmpty(hubName))
			{
				throw new ArgumentException("Must not be null or empty", nameof(hubName));
			}

			return $"{this.endpoint}/client/?hub={hubName}";
		}

		private string GetPublishHubUrl(string hubName)
		{
			if (string.IsNullOrEmpty(hubName))
			{
				throw new ArgumentException("Must not be null or empty", nameof(hubName));
			}

			return $"{this.endpoint}/api/v1/hubs/{hubName}";
		}

		private static void ParseConnectionString(string connectionString, out string endpoint, out string accessKey, out string version)
		{
			if (string.IsNullOrEmpty(connectionString))
			{
				throw new ArgumentException("Must not be null or empty", nameof(connectionString));
			}

			var connectionStringParams = connectionString.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries)
														 .Select(p => p.Split(new[] { '=' }, 2))
														 .ToDictionary(p => p[0].Trim().ToLower(), p => p[1].Trim());

			if (!connectionStringParams.TryGetValue("endpoint", out endpoint))
			{
				throw new ArgumentException("Invalid connection string, missing endpoint.");
			}

			if (!connectionStringParams.TryGetValue("accesskey", out accessKey))
			{
				throw new ArgumentException("Invalid connection string, missing access key.");
			}

			connectionStringParams.TryGetValue("version", out version);
		}

		private string GenerateJwtBearerToken(string issuer, string audience, ClaimsIdentity subject, DateTime? expires)
		{
			SigningCredentials credentials = null;

			if (!string.IsNullOrEmpty(this.accessKey))
			{
				var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(this.accessKey));

				credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
			}

			var token = this.tokenHandler.CreateJwtSecurityToken(
				issuer: issuer,
				audience: audience,
				subject: subject,
				expires: expires,
				signingCredentials: credentials
			);

			return this.tokenHandler.WriteToken(token);
		}
	}
}
