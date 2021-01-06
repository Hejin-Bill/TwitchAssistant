package com.laioffer.jupiter.servlet;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.laioffer.jupiter.db.MySQLConnection;
import com.laioffer.jupiter.db.MySQLException;
import com.laioffer.jupiter.entity.LoginRequestBody;
import com.laioffer.jupiter.entity.LoginResponseBody;
import com.laioffer.jupiter.entity.User;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@WebServlet(name = "LoginServlet", urlPatterns = {"/login"})
public class LoginServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
//        ObjectMapper mapper = new ObjectMapper();
        LoginRequestBody body = new ObjectMapper().readValue(request.getReader(), LoginRequestBody.class);
        if (body == null) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        String userName = "";
        MySQLConnection connection = null;
        try {
            connection = new MySQLConnection();
            String userId = body.getUserId();
            String password = ServletUtil.encryptPassword(userId, body.getPassword());
            userName = connection.verifyLogin(userId, password);
        } catch (MySQLException e) {
            throw new ServletException(e);
        } finally {
            if (connection != null) {
                connection.close();
            }
        }

        if (!userName.isEmpty()){
            HttpSession session = request.getSession();
            session.setAttribute("user_id", body.getUserId());
            session.setMaxInactiveInterval(600);

            LoginResponseBody responseBody = new LoginResponseBody(body.getUserId(), userName);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().print(new ObjectMapper().writeValueAsString(responseBody));
        }else{
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }
}
