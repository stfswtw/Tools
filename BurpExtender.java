package burp;
/***
 *
 功能：
 1.返回包里数据只匹配content-type为text/html或text/htm的响应包，content-type大小写都要匹配content-type ｜ Contype-Type
 2.提取请求包参数值，并匹配响应包里的数据，匹配之前先对请求包数据进行url解码，匹配成功则标记为蓝色。
 3.匹配到的值会显示在Notes中。

 问题：
 1.配到参数: true，1，0，去掉。匹配长度>2位.   已解决
 2.不匹配Cookie里的参数                     已解决
 3.“ ‘ 双引号，单引号匹配好像有点问题。        已解决
 4.POST请求，获取数据转换成字典匹配reaponse数据
 5.不匹配resonse heads字段数据             已解决
 *
 *
 */
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.PrintWriter;



public class BurpExtender implements IBurpExtender, IHttpListener {
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private PrintWriter stdout;//定义输出
    private static final String EXTENSION_NAME = "Xss_Check by stfswtw";
    private static final String[] ALLOWED_CONTENT_TYPES = {"text/html", "text/htm"}; // 允许的 Content-Type

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;//方法里的callbacks赋值到全局，全局使用（IBurpExtenderCallbacks callbacks必须被使用）
        this.helpers = callbacks.getHelpers();//这个必须要有，callbacks对象调用getHelpers()去获取helpers对象，bp规定
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);//输出到控制台
        this.stdout = stdout;//
        callbacks.setExtensionName(EXTENSION_NAME);
        callbacks.registerHttpListener(this);
        callbacks.printOutput("Xss_Check loaded.");
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!messageIsRequest) { // 只处理响应
            byte[] response = messageInfo.getResponse();
            IResponseInfo responseInfo = helpers.analyzeResponse(response);
            //this.stdout.println("返回包里的内容responseInfo:"+responseInfo);//都是字节流

            // 检查 Content-Type
            String contentType = getContentType(responseInfo);
            if (contentType == null || !isAllowedContentType(contentType)) {
                return; // 如果不是 text/html 或 text/htm，退出不执行后续代码
            }

            // 解析请求
            byte[] request = messageInfo.getRequest();
            IRequestInfo requestInfo = helpers.analyzeRequest(request);
            List<IParameter> parameters = requestInfo.getParameters();//方法返回的参数列表
            //this.stdout.println("请求包里的内容requestInfo.getParameters"+parameters);

            // 提取参数值并匹配响应
            for (IParameter param : parameters) {
                //跳过Cookie参数
                if (param.getType() == IParameter.PARAM_COOKIE) {
                    continue;
                }
                String paramValue = param.getValue();
                try {
                    paramValue = java.net.URLDecoder.decode(paramValue, "UTF-8");
                } catch (Exception e) {
                    e.printStackTrace();
                }//对请求包参数做一个url解码
                if (paramValue != null && !paramValue.isEmpty()) {
                    //只匹配response里body的部分
                    //String responseStr = helpers.bytesToString(response);
                    String responseBody = helpers.bytesToString(response).substring(responseInfo.getBodyOffset());

                    if (responseBody.contains(paramValue)) {
                        if (paramValue.contains("true") || paramValue.contains("false") || paramValue.length()<=2) {
                            continue;
                        }
                        // 标记匹配项为紫色
                        callbacks.printOutput("匹配到参数: " + paramValue);
                        messageInfo.setHighlight("blue"); // 标记为蓝色
                        // 将匹配到的参数值更新到 Notes
                        String currentNotes = messageInfo.getComment();
                        if (currentNotes == null || currentNotes.isEmpty()) {
                            messageInfo.setComment("匹配参数: " + paramValue);
                        } else {
                            messageInfo.setComment(currentNotes + "; 匹配参数: " + paramValue);
                        }


                    }
                }
            }
        }
    }

    /**
     * 获取响应的 Content-Type
     */
    private String getContentType(IResponseInfo responseInfo) {
        for (String header : responseInfo.getHeaders()) {
            if (header.toLowerCase().startsWith("content-type:")) {
                return header.substring("content-type:".length()).trim();
            }
        }
        return null;
    }

    /**
     * 检查 Content-Type 是否允许
     */
    private boolean isAllowedContentType(String contentType) {
        for (String allowedType : ALLOWED_CONTENT_TYPES) {
            if (contentType.startsWith(allowedType)) {
                return true;
            }
        }
        return false;
    }




    }
