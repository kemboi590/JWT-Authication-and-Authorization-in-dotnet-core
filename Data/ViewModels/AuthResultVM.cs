﻿namespace JWTAuth.Data.ViewModels
{
    public class AuthResultVM
    {
        public required string Token { get; set; }
        public required string RefreshToken { get; set; }
        public DateTime ExpiresAt { get; set; }
    }
}
