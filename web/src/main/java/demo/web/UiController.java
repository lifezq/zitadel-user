package demo.web;


import lombok.extern.slf4j.Slf4j;
import lombok.var;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.stream.Collectors;

@Slf4j
@Controller
class UiController {

    @GetMapping(value = {"/", "/index"})
    public String showIndex(Model model, Authentication auth, HttpServletRequest request, HttpServletResponse response) {
        var roleNames = auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
        model.addAttribute("roleNames", roleNames);
        return "index";
    }

    @GetMapping("/login")
    public String login() {
        return "/login";
    }
}
