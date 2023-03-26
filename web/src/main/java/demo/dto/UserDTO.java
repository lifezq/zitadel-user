package demo.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

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
    private String username;
    private String email;
    private String password;
    private String role;
}
