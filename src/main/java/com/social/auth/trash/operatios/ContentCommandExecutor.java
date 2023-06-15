package com.social.auth.trash.operatios;

import com.social.auth.trash.utils.Constants;

public class ContentCommandExecutor {

    Command abstractCommand;
    Constants.ID_TYPE idType;

    public ContentCommandExecutor(Command abstractCommand, Constants.ID_TYPE idType) {
        this.abstractCommand = abstractCommand;
        this.idType = idType;
    }

    public void execute() {
        abstractCommand.execute(idType);
    }
}
