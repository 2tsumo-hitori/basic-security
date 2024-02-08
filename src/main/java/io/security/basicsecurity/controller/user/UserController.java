package io.security.basicsecurity.controller.user;

import io.security.basicsecurity.domain.Account;
import io.security.basicsecurity.domain.AccountDto;
import io.security.basicsecurity.service.UserService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @GetMapping("/my-page")
    public String myPage() {
        return "user/my-page";
    }

    @GetMapping("/users")
    public String createUser() {
        return "user/login/register";
    }

    @PostMapping("/users")
    public String createUser(AccountDto accountDto) {
        ModelMapper modelMapper = new ModelMapper();
        Account account = modelMapper.map(accountDto, Account.class);

        account.setPassword(passwordEncoder.encode(account.getPassword()));

        userService.create(account);

        return "redirect:/";
    }
}
