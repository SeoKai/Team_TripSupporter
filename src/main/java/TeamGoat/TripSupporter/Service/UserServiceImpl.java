package TeamGoat.TripSupporter.Service.User;

import TeamGoat.TripSupporter.Config.auth.jwt.JwtTokenProvider;
import TeamGoat.TripSupporter.Config.auth.jwt.TokenInfo;
import TeamGoat.TripSupporter.Domain.Dto.User.UserAndProfileDto;
import TeamGoat.TripSupporter.Domain.Entity.User.JWTToken;
import TeamGoat.TripSupporter.Domain.Entity.User.User;
import TeamGoat.TripSupporter.Domain.Entity.User.UserProfile;
import TeamGoat.TripSupporter.Domain.Enum.UserRole;
import TeamGoat.TripSupporter.Repository.JWTTokenRepository;
import TeamGoat.TripSupporter.Repository.UserProfileRepository;
import TeamGoat.TripSupporter.Repository.UserRepository;
import TeamGoat.TripSupporter.Service.UserService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final JWTTokenRepository jwtTokenRepository;
    private final AuthenticationManager authenticationManager;
    private final UserProfileRepository userProfileRepository;

    @Value("${jwt.secret}")
    private String secretKey;
    @Value("${jwt.expiration}")
    private long jwtExpirationMs;

    @Override
    @Transactional
    public TokenInfo register(UserAndProfileDto userAndProfileDto) {
        // 중복 체크
        if (userRepository.existsByUserEmail(userAndProfileDto.getUserDto().getUserEmail()) ||
                userProfileRepository.existsByUserNickname(userAndProfileDto.getUserProfileDto().getUserNickname())) {
            throw new IllegalArgumentException("이미 사용 중인 이메일 또는 닉네임입니다.");
        }

        // 사용자 엔티티 생성 및 저장
        User user = User.builder()
                .userEmail(userAndProfileDto.getUserDto().getUserEmail())
                .userPassword(passwordEncoder.encode(userAndProfileDto.getUserDto().getUserPassword()))
                .userPhone(userAndProfileDto.getUserDto().getUserPhone())
                .userRole(UserRole.USER)
                .build();
        userRepository.save(user);

        // 사용자 프로필 생성 및 저장
        UserProfile userProfile = UserProfile.builder()
                .user(user)
                .userNickname(userAndProfileDto.getUserProfileDto().getUserNickname())
                .build();
        userProfileRepository.save(userProfile);

        // 인증 객체 생성 및 JWT 토큰 반환
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        userAndProfileDto.getUserDto().getUserEmail(),
                        userAndProfileDto.getUserDto().getUserPassword()
                )
        );
        return jwtTokenProvider.generateToken(authentication);
    }

    @Override
    public TokenInfo login(String userEmail, String password) {
        // 사용자 조회
        User user = userRepository.findByUserEmail(userEmail)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));

        // 비밀번호 확인
        if (!passwordEncoder.matches(password, user.getUserPassword())) {
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
        }

        // 인증 객체 생성 및 JWT 토큰 반환
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(userEmail, password)
        );
        return jwtTokenProvider.generateToken(authentication);
    }

    @Override
    @Transactional
    public void logout(String accessToken) throws IOException {
        if (!jwtTokenProvider.validateToken(accessToken)) {
            throw new IllegalArgumentException("유효하지 않은 토큰입니다.");
        }

        JWTToken tokenEntity = jwtTokenRepository.findByAccessToken(accessToken);
        if (tokenEntity != null) {
            jwtTokenRepository.delete(tokenEntity);
        }
    }

    @Override
    public void findPassword(String email, String phone) {
        // 사용자 조회
        User user = userRepository.findByUserEmailAndUserPhone(email, phone)
                .orElseThrow(() -> new IllegalArgumentException("사용자 정보를 확인할 수 없습니다."));

        // 임시 비밀번호 생성
        String tempPassword = generateTempPassword();

        // 사용자 엔티티 업데이트 및 저장
        User updatedUser = User.builder()
                .userId(user.getUserId())
                .userEmail(user.getUserEmail())
                .userPassword(passwordEncoder.encode(tempPassword))
                .userPhone(user.getUserPhone())
                .userRole(user.getUserRole())
                .userStatus(user.getUserStatus())
                .provider(user.getProvider())
                .providerId(user.getProviderId())
                .build();
        userRepository.save(updatedUser);

        // 이메일 발송 (단순 로그로 대체)
        log.info("임시 비밀번호 [{}]가 이메일 [{}]로 전송되었습니다.", tempPassword, email);
    }

    @Override
    public boolean isEmailDuplicate(String email) {
        return userRepository.existsByUserEmail(email);
    }

    @Override
    public boolean isNicknameDuplicate(String nickname) {
        return userProfileRepository.existsByUserNickname(nickname);
    }

    @Override
    public String findId(String phone) {
        return userRepository.findByUserPhone(phone)
                .map(User::getUserEmail)
                .orElse(null);
    }

    private String generateTempPassword() {
        return UUID.randomUUID().toString().substring(0, 8);
    }
}
