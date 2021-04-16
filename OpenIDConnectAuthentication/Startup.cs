using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.OpenApi.Models;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using System.Net.Http;
using AspNet.Security.OpenIdConnect.Primitives;

namespace OpenIDConnectAuthentication
{
    public class Startup
    {
        private readonly IConfiguration _configuration;

        public Startup(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();

            services.AddDbContext<DataContext>(options =>
            {
                // Configure the context to use Microsoft SQL Server.
                options.UseSqlServer("Data Source=LAPTOP-UHC60CLA;Initial Catalog=openiddict;Integrated Security=True");

                // Register the entity sets needed by OpenIddict.
                // Note: use the generic overload if you need
                // to replace the default OpenIddict entities.
                options.UseOpenIddict();
            });

            services.AddOpenIddict()

                // Register the OpenIddict core components.
                .AddCore(options =>
                {
                    // Configure OpenIddict to use the Entity Framework Core stores and models.
                    // Note: call ReplaceDefaultEntities() to replace the default entities.
                    options.UseEntityFrameworkCore()
                                   .UseDbContext<DataContext>();
                })

                // Register the OpenIddict server components.
                .AddServer(options =>
                {

                    options.RegisterScopes(OpenIdConnectConstants.Scopes.Email,
                        OpenIdConnectConstants.Scopes.OpenId,
                        OpenIdConnectConstants.Scopes.Profile);
                    // Enable the token endpoint.
                    options.SetTokenEndpointUris("/jwt/tokens");
                    options.SetAuthorizationEndpointUris("/authentication");//.RequireProofKeyForCodeExchange();
                    options.AllowRefreshTokenFlow();
                    options.SetRefreshTokenReuseLeeway(TimeSpan.FromMilliseconds(0));
                    options.SetIdentityTokenLifetime(TimeSpan.FromMinutes(1));

                    options.AllowAuthorizationCodeFlow();

                     RSA rsa = RSA.Create();
                    rsa.ImportRSAPrivateKey(
                        source: Convert.FromBase64String(_configuration["jwt:privatekey"]),
                        bytesRead: out int _
                    );

                    // Register the signing and encryption credentials.
                    options.AddSigningKey(new RsaSecurityKey(rsa)).AddEncryptionKey(new RsaSecurityKey(rsa));

                    // Register the ASP.NET Core host and configure the ASP.NET Core options.
                    options.UseAspNetCore()
                                  .EnableTokenEndpointPassthrough()
                                  .EnableAuthorizationEndpointPassthrough();
                })

                // Register the OpenIddict validation components.
                .AddValidation(options =>
                {
                    // Import the configuration from the local OpenIddict server instance.
                    options.UseLocalServer();

                    // Register the ASP.NET Core host.
                    options.UseAspNetCore();
                });

            services.AddScoped<IJwtService, JwtService>();
            services.AddScoped<IClaimsMapper, ClaimsMapper>();
            // Register the worker responsible of seeding the database with the sample clients.
            // Note: in a real world application, this step should be part of a setup script.
            services.AddHostedService<Worker>();

            services.AddControllers();
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "OpenIDConnectAuthentication", Version = "v1" });
            });

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
            .AddCookie(options =>
            {
                options.ExpireTimeSpan = TimeSpan.FromDays(1);
            })
            .AddGoogle("Google", options =>
            {
                options.ClientId = _configuration["Google:client_id"];
                options.ClientSecret = _configuration["Google:client_secret"];
            })
            .AddOpenIdConnect("Microsoft", options =>
            {
                options.Authority = "https://login.live.com";
                options.ResponseType = Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectResponseType.Code;
                options.ResponseMode = Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectResponseMode.FormPost;
                options.ClientId = _configuration["OpenIDConnect:Microsoft:client_id"];
                options.ClientSecret = _configuration["OpenIDConnect:Microsoft:client_secret"];
                options.CallbackPath = "/signin-oidc";
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseSwagger();
                app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "OpenIDConnectAuthentication v1"));
            }

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{Controller}/{action}/{id}");
                endpoints.MapGet("/", async context =>
                {
                    await context.Response.WriteAsync("Hello World!");
                });
            });
        }
    }
}
