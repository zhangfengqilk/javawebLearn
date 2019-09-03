package com.mybatisplus.demo.testmybatisplus.controller;


import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.mybatisplus.demo.testmybatisplus.entity.User;
import com.mybatisplus.demo.testmybatisplus.mapper.UserMapper;
import com.mybatisplus.demo.testmybatisplus.service.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;


/**
 * <p>
 *  前端控制器
 * </p>
 *
 * @author jobob
 * @since 2019-09-03
 */
@RestController
@RequestMapping("/testmybatisplus/user")
public class UserController {
    @Autowired
    private IUserService iuserService;

    @Autowired
    private UserMapper userMapper;
    @GetMapping("/getById/{id}")
    public Object getById(@PathVariable Integer id) {
        /*iuserService.save(new User().setAge(56)
                .setEmail("zhangfengqilk@163.com")
                .setName("Frankie"));*/
        User user=new User();
        user.setAge(12);
        user.setEmail("zhang@163.com");
        user.setName("zhangfengqi");
        userMapper.insert(user);
        List<User> userList = iuserService.lambdaQuery().eq(User::getAge, 18).list();
        return userList;
    }
    @PostMapping("/c")
    public Object c (@Validated User u){
        userMapper.insert(u);
        return "新增数据成功";
    }

    @GetMapping("/r/{age}")
    public Object r (@PathVariable Integer age){
        User user = userMapper.selectOne(new QueryWrapper<User>().eq("name", "zhangfengqi"));
        return user;
    }
    @PostMapping("/u/{name}/{age}")
    public Object u (@PathVariable String name, @PathVariable Integer age){
        User user = iuserService.lambdaQuery().eq(User::getName, name).list().get(0);
        user.setName(name);
        user.setAge(age);
        iuserService.updateById(user);
        return "更新成功";
    }

    @PostMapping("/d/{name}")
    public Object d (@PathVariable String name){
        boolean re = iuserService.remove(new QueryWrapper<User>().eq("name", name));
        return re?"删除成功":"删除失败";
    }



}
