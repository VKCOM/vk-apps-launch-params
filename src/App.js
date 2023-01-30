import React from 'react';
import { Cell, Group, List, Panel, PanelHeader, View, Header, AppRoot } from '@vkontakte/vkui';
import '@vkontakte/vkui/dist/vkui.css';

class App extends React.Component {
    constructor(props) {
        super(props);
    }

    render() {
        const queryParams = new URLSearchParams(window.location.search);
        const hashParams = new URLSearchParams(window.location.hash);

        return (
            <AppRoot>
                <View activePanel="main">
                    <Panel id="main">
                        <PanelHeader>Launch params</PanelHeader>
                        {
                            [
                                {
                                    groupTitle: "Query params",
                                    paramsToShow: queryParams
                                },
                                {
                                    groupTitle: "Hash params",
                                    paramsToShow: hashParams
                                }
                            ].map(({ groupTitle, paramsToShow }) => {
                                return <Group
                                    key={groupTitle}
                                    header={<Header>{groupTitle}</Header>}
                                >
                                    <List>
                                        {
                                            Array.from(paramsToShow.entries()).map(([key, value]) => {
                                                return <Cell
                                                    key={key}
                                                    description={key}
                                                >
                                                    {value || <span style={{ color: "red" }}>–</span>}
                                                </Cell>
                                            })
                                        }
                                    </List>
                                </Group>
                            })
                        }
                    </Panel>
                </View>
            </AppRoot>
        );
    }
}

export default App;
