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
            services.AddDbContext<DataContext>(options =>
                options.UseSqlServer("Data Source=LAPTOP-UHC60CLA;Initial Catalog=master;Integrated Security=True"));

            services.AddScoped<IJwtService, JwtService>();

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
            //.AddMicrosoftAccount("Microsoft", options =>
            //{
            //    options.ClientId = _configuration["OpenIDConnect:Microsoft:client_id"];
            //    options.ClientSecret = _configuration["OpenIDConnect:Microsoft:client_secret"];
            //    options.UsePkce = true;
            //    options.CallbackPath = "/signin-oidc";
            //    options.UserInformationEndpoint = "https://graph.microsoft.com/v1.0/me";
            //});
            .AddOpenIdConnect("Microsoft", options =>
            {
                options.Authority = "https://login.live.com";
                options.ResponseType = Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectResponseType.Code;
                options.ResponseMode = Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectResponseMode.FormPost;
                options.ClientId = _configuration["OpenIDConnect:Microsoft:client_id"];
                options.ClientSecret = _configuration["OpenIDConnect:Microsoft:client_secret"];
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
                endpoints.MapControllers();
                endpoints.MapGet("/", async context =>
                {
                    await context.Response.WriteAsync("Hello World!");
                });
            });
        }
    }
}
