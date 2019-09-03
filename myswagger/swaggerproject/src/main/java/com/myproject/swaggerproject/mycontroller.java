/*
package com.myproject.swaggerproject;

import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping
public class mycontroller {
    @GetMapping("/name")
    public String name()
    {
        return "zhangfengqi";
    }

    @ApiOperation(value="注册", notes="注册用户",tags = "注册用户",httpMethod = "POST")
    @ApiResponses(value = {@ApiResponse(code = 200, message = "成功", response = Void.class),
            @ApiResponse(code = 400, message = "参数错误", response = Void.class),
            @ApiResponse(code = 500, message = "Internal Server Error", response = Void.class)
    })
    @GetMapping(value = "/register/{name}")
    public String postUser(@PathVariable("name") String name) {
        return "hello"+name;

    }
}
*/
