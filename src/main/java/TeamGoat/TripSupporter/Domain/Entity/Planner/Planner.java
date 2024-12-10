package TeamGoat.TripSupporter.Domain.Entity.Planner;

import TeamGoat.TripSupporter.Domain.Entity.Bookmark.BookmarkPlanner;
import TeamGoat.TripSupporter.Domain.Entity.Tag.PlannerTag;
import TeamGoat.TripSupporter.Domain.Entity.Tag.Tag;
import TeamGoat.TripSupporter.Domain.Entity.User.User;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "TBL_PLANNER")
@Getter
@ToString
<<<<<<< HEAD
@NoArgsConstructor(access = AccessLevel.PROTECTED)
=======
@Builder
>>>>>>> eb2400e6ef8985be4db8b9249b3db945c5ea5104
public class Planner {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long plannerId;

    @Column(name = "PLANNER_TITLE", nullable = false, length = 50)
    private String plannerTitle;    //플래너 제목

    @Column(name = "PLANNER_START_DATE", nullable = false)
    private LocalDate plannerStartDate; // 계획 시작 날짜

    @Column(name = "PLANNER_END_DATE", nullable = false)
    private LocalDate plannerEndDate; // 계획 종료 날짜

    @Column(name = "PLANNER_CREATED_AT", updatable = false, columnDefinition = "DATETIME DEFAULT NOW()")
    private LocalDateTime plannerCreatedAt; // 계획 생성 시각

    @Column(name = "PLANNER_UPDATED_AT", columnDefinition = "TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP")
<<<<<<< HEAD
    private LocalDateTime plannerUpdatedAt; // 계획 수정 시각
=======
    private LocalDateTime plannerUpdatedAt; // 계정 수정 시각
>>>>>>> eb2400e6ef8985be4db8b9249b3db945c5ea5104

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "USER_ID", foreignKey = @ForeignKey(name = "FK_USER_PLANNER_IDX"))
    private User user;

    @OneToMany(mappedBy = "planner", cascade = CascadeType.ALL, orphanRemoval = true)
    private Set<PlannerTag> tags = new HashSet<>(); // 태그 정보
    // set을 사용하여 동일planner와 동일 tag쌍의 연결을 방지


    @OneToMany(mappedBy = "planner", cascade = CascadeType.ALL, orphanRemoval = true)
    private Set<BookmarkPlanner> bookmarks = new HashSet<>(); // 북마크 정보
    // set을 사용하여 동일planner와 동일 user쌍의 연결을 방지
<<<<<<< HEAD

    @Builder
    public Planner(Long plannerId, String plannerTitle, LocalDate plannerStartDate, LocalDate plannerEndDate, User user) {
        this.plannerId = plannerId;
        this.plannerTitle = plannerTitle;
        this.plannerStartDate = plannerStartDate;
        this.plannerEndDate = plannerEndDate;
        this.user = user;
        this.plannerCreatedAt = LocalDateTime.now();
        this.plannerUpdatedAt = LocalDateTime.now();
    }
=======
>>>>>>> eb2400e6ef8985be4db8b9249b3db945c5ea5104
}