#filename="C:\Users\Dell\Desktop\DBC-1115\file.txt"
echo "hello"
read -p "Enter gs id: " >gs_id
echo $gs_id
read -p "Enter gs access key: " >gs_access_key
echo $gs_access_key | sha256sum | awk '{print $1}'
#call python code that writes to boto
python C:\\Users\\Dell\\Desktop\\DBC-1115\\write_to_boto.py $gs_id $gs_access_key
echo -n "Credentials saved!"
