import java.io.Serializable;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableMap;

class MyObj implements Serializable{
    int a;
    String b;
    MyObj(int a, String b){
        a = a;
        b = b;
    }
}


// 基础类型测试样例
class HessianDto implements Serializable { 
    private int p1 = 1;
    private Integer p2 = 1;
    private long p3 = 1;
    private Long p4 = 1L;
    private float p5 = 1.1f;
    private Float p6 = 1.1f;
    private double p7 = 1.1;
    private Double p8 = 1.1;
    private String p9 = "xixi";
    private List p10 = Arrays.asList("xixi", "haha");
    private String[] p11 = {"xixi", "haha"};
    private boolean p12 = true;
    private Boolean p13 = true;
    private Map<String, String> p14 = ImmutableMap.<String, String>builder()
            .put("张三", "北京")
            .put("李四", "上海")
            .build();
    private Date p15 = new Date();
    private Byte p16 = 1;
    private byte p17 = 1;
    private List p18 = Arrays.asList(new MyObj(4, "4"), new MyObj(5, "5"));
    private MyObj[] p19 = {new MyObj(4, "4"), new MyObj(5, "5")};
    private MyObj[] p20 = p19;
    private Date p21 = p15;
    private Map<String, String> p22 = p14;
    private String p23 = p9;
    private List p24 = p10;
    private String[] p25 = p11;
}

class MyLinkList implements Serializable{
    int data;
    MyLinkList next;
    MyLinkList(){}
}

class Car implements Serializable { // Map Representation of a Java Object
    String color = "aquamarine";
    String model = "Beetle";
    int mileage = 65536;
  }

public class Test{
    public MyLinkList CircularList(){ // 循环列表
        MyLinkList list = new MyLinkList();
        list.data = 1;
        list.next = list;
        return list;
    }

    public Map sparseArray(){ // A sparse array of Map
        Map map = new HashMap();
        map.put(new Integer(1), "fee");
        map.put(new Integer(16), "fie");
        map.put(new Integer(256), "foe");
        return map;
    }
}