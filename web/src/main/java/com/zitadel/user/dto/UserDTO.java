package com.zitadel.user.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotBlank;

/**
 * @Package demo.dto
 * @ClassName UserDTO
 * @Description TODO
 * @Author Ryan
 * @Date 3/25/2023
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserDTO {
    @NotBlank(message = "用户名不能为空")
    private String username;
    @NotBlank(message = "邮箱不能为空")
    private String email;
    private String password;
    @NotBlank(message = "角色不能为空")
    private String role;
}
