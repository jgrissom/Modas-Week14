using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Modas.Models;

// For more information on enabling MVC for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Modas.Controllers
{
    [Route("api/[controller]"), RequireHttps]
    public class TokenController : Controller
    {
        private UserManager<AppUser> _userManager;
        private IConfiguration _config;

        public TokenController(UserManager<AppUser> userManager, IConfiguration config)
        {
            _config = config;
            _userManager = userManager;
        }

        [HttpPost, AllowAnonymous]
        public async Task<object> RequestToken([FromBody]userModel login)
        {
            // default response 401 Unauthorized
            IActionResult response = Unauthorized();
            if (ModelState.IsValid)
            {
                AppUser user = await _userManager.FindByEmailAsync(login.Username);
                if (user != null)
                {
                    var result = await _userManager.CheckPasswordAsync(user, login.Password);
                    if (result)
                    {
                        // Check for role
                        if (await _userManager.IsInRoleAsync(user, _config["Jwt:Role"]))
                        {
                            var tokenString = BuildToken(user);
                            response = Ok(new { token = tokenString });
                        }
                        else
                        {
                            // 403 Forbidden
                            response = Forbid();
                        }
                    }
                }
            }
            return response;
        }

        private string BuildToken(AppUser user)
        {
            var claims = new List<Claim> {
                //new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.UniqueName, user.Id)
                //new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                //new Claim(JwtRegisteredClaimNames.UniqueName, user.Email)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);

            var token = new JwtSecurityToken(
                null, // issuer
                null, // audience
                claims,
                expires: DateTime.Now.AddDays(Int16.Parse(_config["Jwt:ValidFor"])),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public class userModel
        {
            [Required, EmailAddress]
            public string Username { get; set; }
            [Required]
            public string Password { get; set; }
        }
    }
}
