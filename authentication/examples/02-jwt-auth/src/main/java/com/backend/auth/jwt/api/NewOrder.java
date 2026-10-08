package com.backend.auth.jwt.api;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

record NewOrder(@NotBlank @Size(max = 100) String item, @Min(1) @Max(100) int quantity) {
}
