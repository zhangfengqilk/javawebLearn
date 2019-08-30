package com.test.demo.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * @author lixinjie
 * @since 2018-10-30
 */
@RequestMapping("/example")
@Controller
public class ExampleController {

	@RequestMapping("/index")
	public String index() {
		return "index";
	}
	@RequestMapping("/success")
	public String success() {
		return "success";
	}
	
	@RequestMapping("/failure")
	public String failure() {
		return "failure";
	}
	
	@RequestMapping("/logout")
	public String logout() {
		return "logout";
	}
	
	@RequestMapping("/permit")
	public String permit() {
		return "permit";
	}
	
	@RequestMapping("/nopermit")
	public String nopermit() {
		return "nopermit";
	}
	
	@RequestMapping("/deny")
	public String deny() {
		return "deny";
	}
	
	@RequestMapping("/rolea")
	public String rolea() {
		return "rolea";
	}
	
	@RequestMapping("/roleb")
	public String roleb() {
		return "roleb";
	}
	
	@RequestMapping("/rolec")
	public String rolec() {
		return "rolec";
	}
	
	@RequestMapping("/roled")
	public String roled() {
		return "roled";
	}
}
