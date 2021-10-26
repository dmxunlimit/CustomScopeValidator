package org.wso2.custom.carbon.identity.oauth2.validators;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.validators.OAuth2ScopeValidator;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Properties;

public class OAuthScopeValidatorExtention extends OAuth2ScopeValidator {
    private static final Log log = LogFactory.getLog(OAuthScopeValidatorExtention.class);
    private static final String OPENID = "openid";
    public static final String scope_management_properties = "custom-scope-validator.properties";
    private static OAuthScopeValidatorExtention instance = new OAuthScopeValidatorExtention();

    public static OAuthScopeValidatorExtention getInstance() {
        return instance;
    }

    @Override
    public boolean validateScope(AccessTokenDO accessTokenDO, String resource) throws IdentityOAuth2Exception {
        return true;
    }

    @Override
    public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx) throws
            IdentityOAuth2Exception, UserStoreException {
        String[] requestedScopes = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope();
        String clientId = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId();
        if (requestedScopes != null && requestedScopes.length == 0) {
            log.info("There are no any scopes define in the request");
            return false;
        }
        requestedScopes = (String[]) ArrayUtils.removeElement(requestedScopes, OPENID);

        Properties properties = new Properties();
        String[] arr1 = fetchFromPropertyFile(clientId, properties);
        if (!scopeValidation(arr1, requestedScopes)) {
            return false;
        } else return true;
    }


    public boolean validateScope(OAuthAuthzReqMessageContext authzReqMessageContext) throws
            UserStoreException, IdentityOAuth2Exception {
        return true;
    }

    private boolean scopeValidation(String[] confScopes, String[] reqScopes) {

        if (reqScopes.length > confScopes.length) {
            return false;
        }

        ArrayList<String> verifiedScope = new ArrayList<String>();

        for (int i = 0; i < reqScopes.length; i++) {
            for (int j = 0; j < confScopes.length; j++)
                if (reqScopes[i].equals(confScopes[j])) {
                    verifiedScope.add(reqScopes[i]);
                    break;
                }
        }

        if (reqScopes.length == verifiedScope.size()) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Scopes are matching"));
            }
            return true;
        }
        return false;
    }

    private String[] fetchFromPropertyFile(String propertyName, Properties properties) {

        String configDirPath = CarbonUtils.getCarbonConfigDirPath();
        String scopeConfFile = Paths.get(configDirPath, scope_management_properties).toString();
        File configureFile = new File(scopeConfFile);
        if (!configureFile.exists()) {
            log.warn("scope_management_properties Configuration File is not present at: " + scopeConfFile);
        }
        try {
            properties.load(new FileInputStream(configureFile));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        String[] scopes = properties.getProperty(propertyName).split(",");
        return scopes;
    }
}
