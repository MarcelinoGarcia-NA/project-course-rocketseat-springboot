package br.com.example.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.example.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        var servlet = request.getServletPath();

        if (servlet.startsWith("/tasks/")) {
            var authorization = request.getHeader("Authorization");

            var authorizationUserEncode = authorization.substring("Basic".length()).trim();

            byte[] authorizationDecode = Base64.getDecoder().decode(authorizationUserEncode);

            var auth = new String(authorizationDecode);

            String[] credentials = auth.split(":");
            String userName = credentials[0];
            String password = credentials[1];

            var user = this.userRepository.findByUserName(userName);

            if (user == null) {
                response.sendError(401, "Usuário não autorizado!");
            } else {
                var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
                if (passwordVerify.verified) {
                    request.setAttribute("idUser", user.getId());
                    filterChain.doFilter(request, response);
                } else {
                    response.sendError(401, "Usuário não autorizado!");
                }
            }
        } else {
            filterChain.doFilter(request, response);
        }
    }
}
