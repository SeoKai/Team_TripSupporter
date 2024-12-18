package TeamGoat.TripSupporter.Repository;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * 이메일로 사용자 조회
     *
     * @param email 조회하려는 사용자의 이메일
     * @return 해당 이메일을 가진 사용자의 Optional 객체
     */
    Optional<User> findByEmail(String email);

    /**
     * 이메일 중복 여부 확인
     *
     * @param email 중복 확인하려는 이메일
     * @return 이메일이 이미 존재하면 true, 그렇지 않으면 false
     */
    boolean existsByEmail(String email);
}
