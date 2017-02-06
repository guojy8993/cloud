from cloud.service.image import Image

if __name__ == "__main__":
    image_service = Image()
    result = image_service.image_exists("CentOS-7.2-x86_64-min.raw")
    print result

    result = image_service.image_exists("CentOS-7.2-x86_64-min.qcow2")
    print result
    result = image_service.image_exists("CentOS-7.2-x86_64@snap-CentOS-7.2-x86_64-min.raw")
    print result
