package com.mybatisplus.demo;

import com.baomidou.mybatisplus.core.conditions.Wrapper;
import com.baomidou.mybatisplus.core.conditions.segments.MergeSegments;
//import com.mybatisplus.demo.mapper.UserMapper;
import com.mybatisplus.demo.testmybatisplus.service.IUserService;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import com.mybatisplus.demo.testmybatisplus.entity.User;

import java.util.List;

@RunWith(SpringRunner.class)
@SpringBootTest
public class mptest {
    /*@Autowired
    private UserMapper userMapper;*/

    @Autowired
    private IUserService iUserService;
    @Test
    public void testSelect(){
       /* System.out.println("start select from database___");

        List<User> userList=userMapper.selectList(null);
        Assert.assertEquals(5,userList.size());
        userList.forEach(System.out::println);*/
    }
    @Test
    public void testgeneratedCode(){
        System.out.println("start test generator code");
        List<User> userList = iUserService.lambdaQuery().eq(User::getAge, 18).list();
        Integer id=1;
        User id1 = iUserService.getById(id);
        Assert.assertEquals(1,userList.size());
    }

}
