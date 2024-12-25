package TeamGoat.TripSupporter.Exception;

import jakarta.persistence.EntityNotFoundException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class GlobalExceptionHandler {

    /**
     * IllegalArgumentException 처리
     *
     * @param exception IllegalArgumentException
     * @return ResponseEntity로 사용자에게 반환
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<String> handleIllegalArgumentException(IllegalArgumentException exception) {
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body("잘못된 요청: " + exception.getMessage());
    }

    /**
     * EntityNotFoundException 처리
     *
     * @param exception EntityNotFoundException
     * @return ResponseEntity로 사용자에게 반환
     */
    @ExceptionHandler(EntityNotFoundException.class)
    public ResponseEntity<String> handleEntityNotFoundException(EntityNotFoundException exception) {
        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body("찾을 수 없는 엔티티: " + exception.getMessage());
    }

//    /**
//     * 모든 예외 처리
//     *
//     * @param exception Exception
//     * @return ResponseEntity로 사용자에게 반환
//     */
//    @ExceptionHandler(Exception.class)
//    public ResponseEntity<String> handleGenericException(Exception exception) {
//        return ResponseEntity
//                .status(HttpStatus.INTERNAL_SERVER_ERROR)
//                .body("서버 내부 오류가 발생했습니다. 메시지: " + exception.getMessage());
//    }
}