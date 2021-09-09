using System;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Amazon.AspNetCore.Identity.Cognito;
using Amazon.Extensions.CognitoAuthentication;
using DotNetIdentityWithCognito.Enums;
using DotNetIdentityWithCognito.Helpers;
using DotNetIdentityWithCognito.Model;
using DotNetIdentityWithCognito.Model.RequestModel;
using DotNetIdentityWithCognito.Model.ResponseModel;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace DotNetIdentityWithCognito.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly SignInManager<CognitoUser> _signInManager;
        private readonly CognitoUserManager<CognitoUser> _userManager;
        private readonly ILogger<AuthController> _logger;
        //private readonly RoleManager<CognitoRole> _roleManager;
        private readonly CognitoUserPool _pool;
        private readonly JwtSettings _jwtSettings;
        public AuthController(UserManager<CognitoUser> userManager,
            SignInManager<CognitoUser> signInManager,
            ILogger<AuthController> logger,
            CognitoUserPool pool,
            //RoleManager<CognitoRole> roleManager,
            JwtSettings jwtSettings)
        {
            _userManager = userManager as CognitoUserManager<CognitoUser>;
            _signInManager = signInManager;
            _logger = logger;
            _pool = pool;
            //_roleManager = roleManager;
            _jwtSettings = jwtSettings;
        }

        [HttpPost("registration")]
        public async Task<IActionResult> Register(RegisterRequest signUpRequest)
        {
            try
            {
                var user = _pool.GetUser(signUpRequest.UserName);
                user.Attributes.Add(CognitoAttribute.Email.AttributeName, signUpRequest.Email);

                var result = await _userManager.CreateAsync(user, signUpRequest.Password);
                if (result.Succeeded)
                {
                    _logger.LogInformation("User created a new account with password.");
                    // for role create group in cognito user section and add group name as role name
                    //var findUser = await _userManager.FindByEmailAsync(signUpRequest.Email);
                    //await _userManager.AddToRolesAsync(findUser, new[] { "SuperAdmin" });

                    return Ok();
                }

                List<string> errors = new List<string>();
                foreach (var error in result.Errors)
                {
                    errors.Add(error.Description);
                }

                return BadRequest(errors);
            }
            catch (Exception e)
            {
                return BadRequest(e.Message);
            }

            
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginRequest loginRequest)
        {
            var result = await _signInManager.PasswordSignInAsync(loginRequest.UserName, loginRequest.Password, loginRequest.RememberMe, lockoutOnFailure: false);
            if (result.Succeeded)
            {
                var findUser = await _userManager.FindByNameAsync(loginRequest.UserName);
                JwtSecurityToken jwtSecurityToken = await GenerateJwtToken(findUser);

                LoginResponse response = new LoginResponse
                {
                    Id = findUser.Attributes.FirstOrDefault(a => a.Key == "sub").Value,
                    JwtToken = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                    Email = findUser.Attributes.FirstOrDefault(a => a.Key == "email").Value,
                    UserName = findUser.Username
                };
                var rolesList = await _userManager.GetRolesAsync(findUser);
                response.Roles = rolesList.ToList();
                return Ok(new Response<LoginResponse>(response, $"Authenticated {findUser.Username}"));
            }

            if (result.RequiresTwoFactor)
            {
                // Two Factor code here
            }
            else if (result.IsCognitoSignInResult())
            {
                if (result is CognitoSignInResult cognitoResult)
                {
                    if (cognitoResult.RequiresPasswordChange)
                    {
                        _logger.LogWarning("User password needs to be changed");
                        // password change logic
                    }
                    else if (cognitoResult.RequiresPasswordReset)
                    {
                        _logger.LogWarning("User password needs to be reset");
                        // password change logic
                    }
                }

            }

            return BadRequest("Invalid login attempt.");
        }

        [HttpPost("ConfirmAccount")]
        public async Task<IActionResult> ConfirmAccount(string code, string email)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(email);
                if (user != null)
                {
                    var result = await _userManager.ConfirmSignUpAsync(user, code, true);
                    if (!result.Succeeded)
                    {
                        throw new InvalidOperationException($"Error confirming account for user with UserName '{email}':");
                    }

                    return Ok("User Confirmed, Please Login");
                }

                return BadRequest("No user Found With This Email");
            }
            catch (Exception e)
            {
                return BadRequest(e.Message);
            }
        }

        [HttpGet("forgotPassword")]
        public async Task<IActionResult> ForgotPassword(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
            {
                // Don't reveal that the user does not exist or is not confirmed
                return Ok();
            }

            // Cognito will send notification to user with reset token the user can use to reset their password.
            await user.ForgotPasswordAsync();

            return Ok("Please check your Email for confirmation");
        }

        [HttpPost("resetPassword")]
        public async Task<IActionResult> ResetPassword(ResetPasswordRequest resetPasswordRequest)
        {
            var user = await _userManager.FindByEmailAsync(resetPasswordRequest.Email);
            if (user == null)
            {
                throw new InvalidOperationException($"Unable to retrieve user.");
            }

            var result = await _userManager.ResetPasswordAsync(user, resetPasswordRequest.Token, resetPasswordRequest.Password);

            if (result.Succeeded)
            {
                _logger.LogInformation("Password reset for user with ID '{UserId}'.", user.UserID);
                return Ok("Password Reset Successfully");
            }

            _logger.LogInformation("Unable to rest password for user with ID '{UserId}'.", user.UserID);
            List<string> errors = new List<string>();
            foreach (var item in result.Errors)
            {
                errors.Add(item.Description);
            }
            return BadRequest(errors);
        }

        [HttpPost("changePassword")]
        public async Task<IActionResult> ChangePassword(ChangePasswordRequest changePasswordRequest)
        {
            var user = await _userManager.FindByEmailAsync(changePasswordRequest.Email);
            if (user == null)
            {
                throw new InvalidOperationException($"Unable to retrieve user.");
            }

            var result = await _userManager.ChangePasswordAsync(user, changePasswordRequest.OldPassword, changePasswordRequest.Password);

            if (result.Succeeded)
            {
                _logger.LogInformation("Changed password for user with ID '{UserId}'.", user.UserID);
                return Ok("Password Change Successfully");
            }
            else
            {
                _logger.LogInformation("Unable to change password for user with ID '{UserId}'.", user.UserID);
                List<string> errors = new List<string>();
                foreach (var item in result.Errors)
                {
                    errors.Add(item.Description);
                }
                return BadRequest(errors);
            }
        }

        [HttpGet("logOut")]
        public async Task<IActionResult> LogOut()
        {
            try
            {
                await _signInManager.SignOutAsync();
                return Ok();
            }
            catch (Exception e)
            {
                return BadRequest(e.Message);
            }
        }

        private async Task<JwtSecurityToken> GenerateJwtToken(CognitoUser user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);

            var roleClaims = new List<Claim>();

            foreach (var role in roles)
            {
                roleClaims.Add(new Claim("roles", role));
            }

            var claims = new[]
                {
                    new Claim(ClaimTypes.Email, user.Attributes.FirstOrDefault(a => a.Key == "email").Value),
                    new Claim(ClaimTypes.NameIdentifier, user.Attributes.FirstOrDefault(a => a.Key == "sub").Value),
                    new Claim(ClaimTypes.Name, user.Username),
                    new Claim(ClaimTypes.Sid, Guid.NewGuid().ToString())
                }
                .Union(userClaims)
                .Union(roleClaims);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_jwtSettings.DurationInMinutes),
                signingCredentials: signingCredentials);
            return jwtSecurityToken;
        }
    }
}
