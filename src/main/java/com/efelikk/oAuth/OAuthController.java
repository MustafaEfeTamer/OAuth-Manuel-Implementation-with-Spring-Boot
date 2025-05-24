package com.efelikk.oAuth;

import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Map;

    @Controller
    public class OAuthController {

        @Value("${google.client.id}")       // application.properties'de tanımlanan değişkenleri alıyoruz
        private String clientId;            //  Google'a kayıtlı uygulamamın ID'si

        @Value("${google.client.secret}")
        private String clientSecret;        // Uygulamamın Güvenli erişim için parolası

        @Value("${google.redirect.uri}")
        private String redirectUri;         // Kullanıcı Google'da oturum açtıktan sonra geri döneceği URL

        private final RestTemplate restTemplate = new RestTemplate();

        @GetMapping("/login")               // Giriş Sayfası
        public String home() {
            return "custom-login";
        }

        @GetMapping("/oauth2/authorize")            // Google’a Yönlendirme
        public String authorize() {
            String authUrl = UriComponentsBuilder.fromUriString("https://accounts.google.com/o/oauth2/v2/auth")
                    .queryParam("client_id", clientId)      // Uygulama ID'si
                    .queryParam("redirect_uri", redirectUri)    // Oturum açtıktan sonra yönlendirilcek URL
                    .queryParam("response_type", "code") // Google, login işleminden sonra bir code verir, bu code ile access token alırız.
                    .queryParam("scope", "openid profile email")  // Hangi bilgilere erişim isteniyor (isim, e-posta, fotoğraf)
                    .queryParam("access_type", "offline")  // Bu parametre refresh_token almak istiyorsak gereklidir.
                    .queryParam("prompt", "consent")  // Kullanıcıya her seferinde izin ekranı gösterilir
                    .build().toUriString();

            return "redirect:" + authUrl;
        }

        @GetMapping("/oauth2/callback")       // Google'dan Gelen Kodla Token Alma
        public String callback(String code, HttpSession session) {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            // Googledan gelen kodu da ekleyerek form olusturuyoruz
            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add("code", code);         // Google’ın bize verdiği yetkilendirme kodu
            form.add("client_id", clientId);    // Uygulama ID'si
            form.add("client_secret", clientSecret);     // Uygulama parolası
            form.add("redirect_uri", redirectUri);         // oturum açtıktan sonra yönlendirilcek URL
            form.add("grant_type", "authorization_code");       // Token alma yöntemimiz

            // form ile request olustur
            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);
            // Request ile Authorization kodu kullanarak access token almak
            ResponseEntity<Map> tokenResponse = restTemplate.postForEntity("https://oauth2.googleapis.com/token", request, Map.class);
            String accessToken = (String) tokenResponse.getBody().get("access_token");

            // Access token ile bir request olusturuyoruz
            HttpHeaders userHeaders = new HttpHeaders();
            userHeaders.setBearerAuth(accessToken);
            HttpEntity<Void> userRequest = new HttpEntity<>(userHeaders);

            // Request ile access token kullanarak kullanıcı bilgilerini alıyoruz
            ResponseEntity<Map> userInfoResponse = restTemplate.exchange(
                    "https://www.googleapis.com/oauth2/v3/userinfo",
                    HttpMethod.GET,
                    userRequest,
                    Map.class
            );

            Map<String, Object> userInfo = userInfoResponse.getBody();

            // Kullanıcı bilgilerini Session'a koyuyoruz
            session.setAttribute("name", userInfo.get("name"));
            session.setAttribute("email", userInfo.get("email"));
            session.setAttribute("picture", userInfo.get("picture"));

            return "redirect:/profile";
        }

        @GetMapping("/profile")
        public String profile(Model model, HttpSession session) {
            model.addAttribute("name", session.getAttribute("name"));
            model.addAttribute("email", session.getAttribute("email"));
            model.addAttribute("photo", session.getAttribute("picture"));
            return "user-profile";
        }
    }

