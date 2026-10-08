package com.backend.auth.apikeys.api;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record NewOrder(@NotBlank @Size(max = 100) String item, @Min(1) @Max(1000) int quantity) {
}
