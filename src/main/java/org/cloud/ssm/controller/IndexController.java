package org.cloud.ssm.controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.cloud.ssm.common.ResponseMessage;
import org.cloud.ssm.service.IUserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class IndexController {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(IndexController.class);

	@Autowired
	IUserService userService;

	@GetMapping(value = { "/", "/index" })
	public String getIndexPage(Model model) {
		model.addAttribute("users", userService.getAllUsers());
		LOGGER.debug("index");
		return "index";
	}
	
	@GetMapping(value = { "/home" })
	@ResponseBody
    public ResponseMessage getHomePage(Model model) {
	    ResponseMessage rMessage = new ResponseMessage();
	    rMessage.setMsg("sdfsadf");
        return rMessage;
    }
	
	@GetMapping("/article")
	@ResponseBody
    public ResponseMessage article() {
        Subject subject = SecurityUtils.getSubject();
        if (subject.isAuthenticated()) {
            return new ResponseMessage(200, "You are already logged in");
        } else {
            return new ResponseMessage(200, "You are guest");
        }
    }
}
