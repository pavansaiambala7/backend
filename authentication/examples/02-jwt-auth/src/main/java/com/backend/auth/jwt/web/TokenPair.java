package com.backend.auth.jwt.web;

import com.backend.auth.jwt.refresh.IssuedRefreshToken;
import com.backend.auth.jwt.token.AccessToken;

record TokenPair(AccessToken accessToken, IssuedRefreshToken refreshToken) {
}
