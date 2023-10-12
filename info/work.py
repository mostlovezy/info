import numpy as np
#定义眀密文类
class Text():
    def __init__(self,array=None) -> None:
        self.n=8
        if array is None:
            self.array = np.array([i for i in range(self.n)]#眀密文索引从0开始
                                , dtype=np.int8)
        else:
            self.array=array 
 
class Plaintext(Text):
    def __init__(self,array) -> None:
        super().__init__(array)
        self.P = self.array

class Ciphertext(Text):
    def __init__(self,array) -> None:
        super().__init__(array)
        self.C = self.array


#定义初始与最终置换
def IP(text:Text)->Text:
    old=text
    index=(2,6,3,1,4,8,5,7)
    index=tuple(value-1 for value in index)
    new=Text()
    for i,j in enumerate(index):
        new.array[i]=old.array[j]

    return new
def Inverse_IP(text:Text)->Text:
    old=text
    index=(4,1,3,5,7,2,8,6)
    index=tuple(value-1 for value in index) 
    new=Text()
    for i,j in enumerate(index):
        new.array[i]=old.array[j]

    return new

#密钥
class Key():
    def __init__(self,length:int,key=None) -> None:
        self.length=length
        if key is None:
            self.key = np.array([i for i in range(length)],#密钥索引从0开始
                           dtype=np.int8)
        else:
            self.key=key

def P_10(key:Key)->Key:
    old=key
    index=(3,5,2,7,4,10,1,9,8,6)        
    index=tuple(value-1 for value in index) 
    new=Key(length=10)
    for i,j in enumerate(index):
        new.key[i]=old.key[j]

    return new
def P_8(key:Key)->Key:
    old=key
    index=(6,3,7,4,8,5,10,9)    
    index=tuple(value-1 for value in index) 
    new=Key(length=8)
    for i in range(8):
        new.key[i]=old.key[index[i]]

    return new

def left_shift(key:Key,shift_amount=1)->Key:
    d=shift_amount #左移位数
    old=key
    new=Key(old.length)

    for i in range(5):#0-4
        new.key[(i-d)%5]=old.key[i]
        new.key[(i-d)%5+5]=old.key[i+5]
    
    return new

def get_k1(K:Key)->Key:
    after_P10=P_10(K)
    after_shift=left_shift(after_P10,shift_amount=1)
    after_P8=P_8(after_shift)

    return after_P8

def get_k2(K:Key)->Key:
    after_P10=P_10(K)
    after_shift=left_shift(after_P10,shift_amount=2)
    after_P8=P_8(after_shift)
    return after_P8

class S_DES_fk():
    #key:Key 对应ki
    def __init__(self,key:Key,text:Text) -> None: 
        self.EPBox=[4,1,2,3,2,3,4,1]
        self.SBox_1=[[[0,1],[0,0],[1,1],[1,0]],
                     [[1,1],[1,0],[0,1],[0,0]],
                     [[0,0],[1,0],[0,1],[1,1]],
                     [[1,1],[0,1],[0,0],[1,0]]]
        
        self.SBox_2=[[[0,0],[0,1],[1,0],[1,1]],
                     [[1,0],[1,1],[0,1],[0,0]],
                     [[1,1],[0,0],[0,1],[0,0]],
                     [[1,0],[0,1],[0,0],[1,1]]]
        
        self.SPBox=[2,4,3,1]

        self.key=key
        self.L_text=text.array[0:len(text.array)//2].copy()
        self.R_text=text.array[len(text.array)//2:len(text.array)].copy()
        

    def fun_EPBox(self)->np.array:
        old=self.R_text
        index=self.EPBox
        index=tuple(value-1 for value in index) 
        new=Text()
        for i,j in enumerate(index):
            new.array[i]=old[j]

        return new.array
    
    def fun_XOR(self)->np.array:
        array_1=self.fun_EPBox()
        array_2=self.key.key
        result=array_1^array_2 # 使用^进行元素级异或操作

        return result
    

    def fun_S_Boxs(self)->np.array:
        array=self.fun_XOR()
        i=array[0]*2+array[3]
        j=array[1]*2+array[2]
        res1=self.SBox_1[i][j]

        i=array[4]*2+array[7]
        j=array[5]*2+array[6]
        res2=self.SBox_2[i][j]

        result=res1+res2

        return result
    
    def fun_SPBox(self)->np.array:
        old=self.fun_S_Boxs()
        index=self.SPBox
        index=tuple(value-1 for value in index)
        new=np.array([0,0,0,0])
        for i,j in enumerate(index):
            new[i]=old[j]

        return new


    #轮函数F输出结果
    def fun_F(self)->np.array:
        return self.fun_SPBox()

    #S-DES函数最终输出值
    def output(self)->Text:
        array_F=self.fun_F()
        res_XOR=self.L_text^array_F
        output = np.concatenate((res_XOR, self.R_text))
        return Text(output)

    def outputAfterSWAP(self)->Text:
        array_F=self.fun_F()
        res_XOR=self.L_text^array_F
        output = np.concatenate((self.R_text, res_XOR))
        return Text(output)

#测试
#加密
plain_text=Plaintext(np.array([1,0,1,1,1,0,0,1]))
K=Key(length=10,key=np.array([1,0,0,0,1, 0,1,0,1,0]))

after_IP=IP(plain_text)

k1=get_k1(K)
fk1=S_DES_fk(key=k1, text=after_IP)
after_fk1AndSWAP=fk1.outputAfterSWAP()

k2=get_k2(K)
fk2=S_DES_fk(key=k2, text=after_fk1AndSWAP)
after_fk2=fk2.output()

after_inverseIP=Inverse_IP(after_fk2)

cipher_text=Ciphertext(after_inverseIP.array) #[0, 1, 0, 1, 1, 0, 0, 0]

# print(f'明文:  {plain_text.array} \n开始加密: \n获得密文:  {cipher_text.array}')

#解密
after_IP=IP(cipher_text)

fk2=S_DES_fk(key=k2, text=after_IP)
after_fk2AndSWAP=fk2.outputAfterSWAP()

fk1=S_DES_fk(key=k1, text=after_fk2AndSWAP)
after_fk1=fk1.output()

after_inverseIP=Inverse_IP(after_fk1)

plain_text2=Plaintext(after_inverseIP.array)

# print(f'开始解密: \n获得明文:  {plain_text2.array}')
