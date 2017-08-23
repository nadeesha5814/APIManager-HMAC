package com.sample.mediators; /**
 * Created by Nadeesha on 26-Jul-17.
 */

import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.mediators.AbstractMediator;
import org.apache.synapse.rest.RESTConstants;

import java.util.Map;
import java.util.logging.Logger;

public class CustomHMAC extends AbstractMediator {
    static final String CLIENT_ID = "clientId";
    static final String CLIENT_SECRET = "clientSecret";
    static final String CONTENT_TYPE = "ContentType";
    static final String GET = "GET";
    static final String POST = "POST";

    private static final Logger log = Logger.getLogger(CustomHMAC.class.getName() );

    @Override
    public boolean mediate(MessageContext messageContext) {
        String clientId = (String) messageContext.getProperty(CLIENT_ID);
        String clientSecret = (String) messageContext.getProperty(CLIENT_SECRET);

        String method = (String) messageContext.getProperty("api.ut.HTTP_METHOD");

        String contentType="";
        String body = "";

        if (method.toUpperCase().equals(POST)) {
            Axis2MessageContext axis2MessageContext = (Axis2MessageContext) messageContext;
            contentType=(String) axis2MessageContext.getAxis2MessageContext().getLocalProperty(CONTENT_TYPE);
            body= axis2MessageContext.getEnvelope().toString();
        }


        String api_context= (String) messageContext.getProperty(RESTConstants.REST_SUB_REQUEST_PATH);

        HMACCreator hmacCreator = new HMACCreator();
        hmacCreator.config(clientId, clientSecret);
        Map<String, String> headers = hmacCreator.setHeaders(method,api_context,body,contentType);

        setHeaders(messageContext,headers);
                return true;
    }



    private static void setHeaders (MessageContext messageContext, Map headers) {
        messageContext.setProperty(HMACCreator.AUTHORIZATION_HEADER, headers.get(HMACCreator.AUTHORIZATION_HEADER));
        messageContext.setProperty(HMACCreator.DATE_HEADER, headers.get(HMACCreator.DATE_HEADER));

    }



}


