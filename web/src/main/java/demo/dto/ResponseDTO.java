package demo.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

/**
 * @Package demo.dto
 * @ClassName ResponseDTO
 * @Description TODO
 * @Author Ryan
 * @Date 3/27/2023
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ResponseDTO<T> {
    @Builder.Default
    private int code = HttpStatus.OK.value();
    @Builder.Default
    private String message = HttpStatus.OK.getReasonPhrase();
    private T data;
}
