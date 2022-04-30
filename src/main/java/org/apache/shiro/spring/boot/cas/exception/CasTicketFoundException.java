/*
 * Copyright (c) 2017, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shiro.spring.boot.cas.exception;

import org.apache.shiro.authc.AuthenticationException;

public class CasTicketFoundException extends AuthenticationException {

    /**
     *
     */
    private static final long serialVersionUID = 5804347841925337928L;

    public CasTicketFoundException() {
        super();
    }

    public CasTicketFoundException(String message, Throwable cause) {
        super(message, cause);
    }

    public CasTicketFoundException(String message) {
        super(message);
    }

    public CasTicketFoundException(Throwable cause) {
        super(cause);
    }
}
