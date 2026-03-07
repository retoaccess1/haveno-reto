/*
 * This file is part of Bisq.
 *
 * Bisq is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at
 * your option) any later version.
 *
 * Bisq is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Bisq. If not, see <http://www.gnu.org/licenses/>.
 */

package haveno.daemon.grpc.interceptor;

import com.google.inject.Inject;
import haveno.common.config.Config;
import io.grpc.Metadata;
import static io.grpc.Metadata.ASCII_STRING_MARSHALLER;
import static io.grpc.Metadata.Key;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import static io.grpc.Status.UNAUTHENTICATED;
import io.grpc.StatusRuntimeException;
import static java.lang.String.format;
import lombok.extern.slf4j.Slf4j;

/**
 * Authorizes rpc server calls by comparing the value of the caller's
 * {@value PASSWORD_KEY} header to an expected value set at server startup time.
 *
 * If no password has been configured (--apiPassword is empty) every call is
 * rejected unconditionally. An empty password provides no authentication and
 * would allow any process that can reach the gRPC port to control the daemon.
 *
 * @see haveno.common.config.Config#apiPassword
 */
@Slf4j
public class PasswordAuthInterceptor implements ServerInterceptor {

    private static final String PASSWORD_KEY = "password";
    private static final String NO_PASSWORD_MSG =
            "The gRPC API password is not set. " +
            "Start the daemon with --apiPassword=<password> to enable API access. " +
            "Accepting requests without a password would allow any local process " +
            "to control the daemon.";

    private final String expectedPasswordValue;

    @Inject
    public PasswordAuthInterceptor(Config config) {
        this.expectedPasswordValue = config.apiPassword;
        if (expectedPasswordValue.isEmpty()) {
            log.warn("No API password configured (--apiPassword). " +
                    "All gRPC API calls will be rejected until a password is set.");
        }
    }

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(ServerCall<ReqT, RespT> serverCall,
                                                                 Metadata headers,
                                                                 ServerCallHandler<ReqT, RespT> serverCallHandler) {
        // Reject all calls if no password has been configured. An empty password
        // is indistinguishable from no authentication at all.
        if (expectedPasswordValue.isEmpty())
            throw new StatusRuntimeException(UNAUTHENTICATED.withDescription(NO_PASSWORD_MSG));

        var actualPasswordValue = headers.get(Key.of(PASSWORD_KEY, ASCII_STRING_MARSHALLER));

        if (actualPasswordValue == null)
            throw new StatusRuntimeException(UNAUTHENTICATED.withDescription(
                    format("missing '%s' rpc header value", PASSWORD_KEY)));

        if (!actualPasswordValue.equals(expectedPasswordValue))
            throw new StatusRuntimeException(UNAUTHENTICATED.withDescription(
                    format("incorrect '%s' rpc header value", PASSWORD_KEY)));

        return serverCallHandler.startCall(serverCall, headers);
    }
}
