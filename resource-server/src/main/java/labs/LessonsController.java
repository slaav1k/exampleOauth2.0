package labs;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;

@RestController
public class LessonsController {

    @GetMapping("/lessons")
    public List<Lesson> getLessons() {
        return Arrays.asList(
                new Lesson(
                        "Beginner Golf Basics",
                        "An introduction to the fundamentals of golf.",
                        "John Doe",
                        LocalDateTime.of(2024, 11, 5, 10, 0)
                ),
                new Lesson(
                        "Advanced Swing Techniques",
                        "Improve your swing with advanced techniques.",
                        "Jane Smith",
                        LocalDateTime.of(2024, 11, 6, 14, 0)
                ),
                new Lesson(
                        "Java para Macacos",
                        "Improve your java programming.",
                        "Jane Smith",
                        LocalDateTime.of(2024, 11, 5, 13, 0)
                )
        );
    }

}
