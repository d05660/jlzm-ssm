package org.cloud.ssm.controller;

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
}
