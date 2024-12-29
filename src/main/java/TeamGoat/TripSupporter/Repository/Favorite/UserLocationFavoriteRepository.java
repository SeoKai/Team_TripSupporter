package TeamGoat.TripSupporter.Repository.Favorite;

import TeamGoat.TripSupporter.Domain.Entity.Favorite.UserLocationFavorite;
import TeamGoat.TripSupporter.Domain.Entity.Location.Location;
import TeamGoat.TripSupporter.Domain.Entity.User.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface UserLocationFavoriteRepository extends JpaRepository<UserLocationFavorite , Long> {

    boolean existsByUserAndLocation(User user, Location location);

    Optional<UserLocationFavorite> findByUserAndLocation(User user, Location location);

    Page<UserLocationFavorite> findByUser_UserId(Long user, Pageable pageable);

    long countByLocation_locationId(Long locationId);
}
