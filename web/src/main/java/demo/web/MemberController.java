package demo.web;


import demo.dto.UserDTO;
import demo.model.Users;
import demo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Controller
@RequestMapping("member")
public class MemberController {
    @Autowired
    private UserRepository userRepository;

    @GetMapping("/localList")
    public String localList(Model model) {
        List<Users> items = new ArrayList<>();
        Iterable<Users> users = userRepository.findAll();
        users.forEach(x -> items.add(x));
        model.addAttribute("items", items);
        return "/member/localList";
    }

    @GetMapping("/addLocal")
    public String addLocal() {
        return "/member/addLocal";
    }

    @PostMapping(value = "/addLocal", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public String addLocalPost(@ModelAttribute UserDTO userDTO, Model model) {
        try {
            Users users = Users.builder()
                    .name(userDTO.getUsername())
                    .email(userDTO.getEmail())
                    .password(userDTO.getPassword())
                    .roles(userDTO.getRole())
                    .address("China")
                    .state((short) 1).build();
            userRepository.save(users);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return this.localList(model);
    }

    @GetMapping("/localDelete/{id}")
    @ResponseBody
    public String localDelete(@PathVariable Long id, Authentication auth) {
        Optional<Users> user = userRepository.findById(id);
        if (user.isPresent() && auth.getName().equals(user.get().getName())) {
            return "不能删除当前登录用户";
        }
        userRepository.deleteById(id);
        return "ok";
    }
}
